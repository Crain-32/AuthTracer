package dev.crain.authtracer.system;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Observation;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.TraceSource;
import dev.crain.authtracer.link.TraceSpan;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.ProjectScans;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The whole loop: the brokers (in Docker), Zipkin and the example services as real processes, real users and tokens,
 * then scan and link. Ports are shifted (Kafka 19092, RabbitMQ 15672, Zipkin 19411, identity-service 19000,
 * employee-service 18082 with gRPC on 19082, profile-service 18081, payroll-service 18083) so a dev setup can keep
 * running. payroll-service is the reactive (WebFlux) one.
 */
class EndToEndSystemTests {

    private static final Path SERVICES = Path.of(System.getProperty("authtracer.services.dir"));
    private static final Path LOGS = Path.of("build", "system-test-logs");
    private static final URI ZIPKIN = URI.create("http://localhost:19411");
    private static final URI ISSUER = URI.create("http://localhost:19000");
    private static final URI SERVICE_A = URI.create("http://localhost:18081");
    private static final URI SERVICE_B = URI.create("http://localhost:18082");
    private static final URI SERVICE_D = URI.create("http://localhost:18083");
    private static final int KAFKA_PORT = 19092;
    private static final int RABBITMQ_PORT = 15672;
    private static final int EMPLOYEE_GRPC_PORT = 19082;

    private static final List<AutoCloseable> processes = new ArrayList<>();
    private static final Map<String, Integer> statuses = new java.util.LinkedHashMap<>();
    private static final Map<String, String> bodies = new java.util.LinkedHashMap<>();
    private static SystemGraph system;

    @BeforeAll
    static void runTheSystem() {
        processes.add(Brokers.start(Path.of(System.getProperty("authtracer.brokers.compose")), KAFKA_PORT, RABBITMQ_PORT,
                LOGS));
        processes.add(ManagedProcess.start("zipkin", Path.of(System.getProperty("authtracer.zipkin.jar")), List.of(),
                Map.of("QUERY_PORT", "19411"), LOGS, ZIPKIN.resolve("/health")));
        processes.add(ManagedProcess.start("identity-service", jar("identity-service"), List.of("--server.port=19000",
                "--spring.security.oauth2.authorizationserver.issuer=" + ISSUER), Map.of(), LOGS,
                ISSUER.resolve("/.well-known/openid-configuration")));
        List<String> resourceServer = List.of("--spring.security.oauth2.resourceserver.jwt.issuer-uri=" + ISSUER,
                "--management.tracing.export.zipkin.endpoint=" + ZIPKIN.resolve("/api/v2/spans"),
                "--spring.kafka.bootstrap-servers=localhost:" + KAFKA_PORT, "--spring.rabbitmq.port=" + RABBITMQ_PORT);
        processes.add(ManagedProcess.start("employee-service", jar("employee-service"), concat(resourceServer,
                "--server.port=18082", "--spring.grpc.server.port=" + EMPLOYEE_GRPC_PORT), Map.of(), LOGS,
                SERVICE_B.resolve("/actuator/health")));
        processes.add(ManagedProcess.start("profile-service", jar("profile-service"), concat(resourceServer,
                "--server.port=18081", "--employee-service.base-url=" + SERVICE_B), Map.of(), LOGS,
                SERVICE_A.resolve("/actuator/health")));
        // payroll-service gets its own token from identity-service for its Kafka listener's calls.
        processes.add(ManagedProcess.start("payroll-service", jar("payroll-service"), concat(resourceServer,
                "--server.port=18083",
                "--spring.grpc.client.channel.employee-service.target=static://localhost:" + EMPLOYEE_GRPC_PORT,
                "--spring.security.oauth2.client.provider.identity-service.token-uri=" + ISSUER.resolve("/oauth2/token")),
                Map.of(), LOGS, SERVICE_D.resolve("/actuator/health")));

        TokenDriver tokens = new TokenDriver(ISSUER);
        // profile-service reads profiles over GraphQL and compensation over REST, and sends the admin's view to
        // employee-service's audit over RabbitMQ.
        for (String user : List.of("alice", "carol", "admin")) {
            String token = tokens.accessToken(user);
            get(user, token, SERVICE_A, "/profiles/1");
            get(user, token, SERVICE_A, "/admin/compensation/1");
        }
        get("bob", tokens.accessToken("bob"), SERVICE_A, "/profiles");
        // payroll-service calls employee-service over gRPC once for /teams/1 and once per member (2) for the admin's
        // payroll.
        String alice = tokens.accessToken("alice");
        get("alice", alice, SERVICE_D, "/teams/1");
        get("alice", alice, SERVICE_D, "/teams/1/payroll");
        String admin = tokens.accessToken("admin");
        get("admin", admin, SERVICE_D, "/teams/1/payroll");
        get("bob", tokens.accessToken("bob"), SERVICE_D, "/directory/teams");
        // employee-service sends the salary change to payroll-service over Kafka, whose listener reads the employee
        // back over gRPC with payroll-service's own token: one more gRPC call.
        send("admin", admin, HttpRequest.newBuilder(SERVICE_B.resolve("/admin/employees/1/salary"))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString("{\"salary\": 85000}")), "PUT /admin/employees/1/salary");

        TraceSource traces = awaitTraces(ZipkinTraces.api(ZIPKIN, Duration.ofMinutes(10), 1000),
                Map.of("profile-service", 5, "payroll-service", 4));
        List<ApplicationGraph> graphs = List.of(scan("profile-service"), scan("employee-service"), scan("payroll-service"));
        system = new Linker().link(graphs, traces);

        // The listeners have run (their spans are in): what they kept.
        get("carol", tokens.accessToken("carol"), SERVICE_B, "/audit/employees/1/views");
        get("admin", admin, SERVICE_D, "/payroll/changes");
    }

    @AfterAll
    static void stopTheSystem() throws Exception {
        for (AutoCloseable process : processes.reversed()) {
            process.close();
        }
    }

    @Test
    void trafficBehavedAsTheContractSays() {
        assertThat(statuses).containsEntry("alice /profiles/1", 200)
                .containsEntry("alice /admin/compensation/1", 403)
                .containsEntry("carol /admin/compensation/1", 403)
                .containsEntry("admin /admin/compensation/1", 200)
                .containsEntry("bob /profiles", 200)
                .containsEntry("alice /teams/1", 200)
                .containsEntry("alice /teams/1/payroll", 403)
                .containsEntry("admin /teams/1/payroll", 200)
                .containsEntry("bob /directory/teams", 200)
                .containsEntry("admin PUT /admin/employees/1/salary", 200)
                .containsEntry("carol /audit/employees/1/views", 200)
                .containsEntry("admin /payroll/changes", 200);
    }

    @Test
    void theBrokersDeliveredWhoActed() {
        // The listeners run with no one signed in: who acted travels in the message.
        assertThat(bodies.get("carol /audit/employees/1/views")).contains("\"viewedBy\":\"admin\"");
        assertThat(bodies.get("admin /payroll/changes")).contains("\"changedBy\":\"admin\"");
        // With no one behind it, payroll-service read the name with its own token.
        assertThat(bodies.get("admin /payroll/changes")).contains("\"employeeName\":\"Alice Anders\"");
    }

    @Test
    void tracesConfirmEveryCrossServiceLink() {
        assertThat(system.links()).hasSize(7).allSatisfy(link ->
                assertThat(link.kind()).isEqualTo(Edge.Kind.NETWORK_OBSERVED));
        assertThat(system.links()).extracting(link -> SystemGraph.serviceOf(link.from()), Edge::to).containsExactlyInAnyOrder(
                org.assertj.core.groups.Tuple.tuple("profile-service", "employee-service/ingress:GET /employees/{id}"),
                org.assertj.core.groups.Tuple.tuple("profile-service", "employee-service/ingress:QUERY employee"),
                org.assertj.core.groups.Tuple.tuple("profile-service", "employee-service/ingress:QUERY employees"),
                org.assertj.core.groups.Tuple.tuple("profile-service", "employee-service/ingress:RABBIT audit.compensation-viewed"),
                // One with the caller's token, one with payroll-service's own.
                org.assertj.core.groups.Tuple.tuple("payroll-service",
                        "employee-service/ingress:GRPC employees.v1.EmployeeDirectory/GetEmployee"),
                org.assertj.core.groups.Tuple.tuple("payroll-service",
                        "employee-service/ingress:GRPC employees.v1.EmployeeDirectory/GetEmployee"),
                org.assertj.core.groups.Tuple.tuple("employee-service", "payroll-service/ingress:KAFKA employee.salary-changed"));
    }

    @Test
    void everyRuntimeDecisionMatchesAStaticLocation() {
        // The one finding is decision 0021's: the listener's call with payroll-service's own token is checked as
        // payroll-service.
        assertThat(system.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.BYPASSED);
            assertThat(finding.message()).startsWith("payroll-service calls employee-service GRPC"
                    + " employees.v1.EmployeeDirectory/GetEmployee with its own OAuth2 client token");
        });
    }

    @Test
    void observationsCountGrantsAndDenials() {
        Observation adminRule = observation("profile-service/location:HTTP_REQUEST:", "/admin/**");
        assertThat(adminRule.granted()).isEqualTo(1);
        assertThat(adminRule.denied()).isEqualTo(2);
        Observation ssn = observation("employee-service/location:FIELD:", "getSsn");
        assertThat(ssn.granted()).isPositive();
        assertThat(ssn.denied()).isPositive();
    }

    @Test
    void reactiveDecisionsAreObservedToo() {
        Observation payrollRule = observation("payroll-service/location:HTTP_REQUEST:", "/teams/*/payroll");
        assertThat(payrollRule.granted()).isEqualTo(1);
        assertThat(payrollRule.denied()).isEqualTo(1);
    }

    @Test
    void testIdentitiesShowWhatTheirRequestsNeverNeeded() {
        // Traces name no user: alice and bob hold the same authorities, so they are one identity.
        assertThat(system.identities()).filteredOn(identity -> identity.authorities().contains("SCOPE_openid"))
                .isNotEmpty().allSatisfy(identity -> {
                    assertThat(identity.unneeded()).contains("SCOPE_openid", "SCOPE_profile");
                    assertThat(identity.authorities()).noneMatch(authority -> authority.startsWith("FACTOR_"));
                });
        // payroll-service's own token holds only the scope its client is registered for, and needs it.
        assertThat(system.identities()).filteredOn(identity -> !identity.authorities().contains("SCOPE_openid"))
                .singleElement().satisfies(service -> {
                    assertThat(service.authorities()).containsExactly("SCOPE_employees.read");
                    assertThat(service.needed()).containsExactly("SCOPE_employees.read");
                    assertThat(service.unneeded()).isEmpty();
                    assertThat(service.endpoints())
                            .containsExactly("employee-service GRPC employees.v1.EmployeeDirectory/GetEmployee");
                });
        assertThat(system.identities()).filteredOn(identity -> identity.authorities().contains("ROLE_ADMIN"))
                .isNotEmpty().anySatisfy(admin -> {
                    assertThat(admin.needed()).contains("ROLE_ADMIN");
                    assertThat(admin.endpoints()).contains("profile-service GET /admin/compensation/{id}");
                });
    }

    private static Observation observation(String prefix, String contains) {
        return system.observations().stream()
                .filter(observation -> observation.subject().startsWith(prefix)
                        && observation.subject().contains(contains))
                .findFirst().orElseThrow(() -> new AssertionError("No observation like " + prefix + "*" + contains
                        + " in " + system.observations()));
    }

    private static void get(String user, String token, URI service, String path) {
        send(user, token, HttpRequest.newBuilder(service.resolve(path)).GET(), path);
    }

    private static void send(String user, String token, HttpRequest.Builder request, String call) {
        try {
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    request.header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
            statuses.put(user + " " + call, response.statusCode());
            bodies.put(user + " " + call, response.body());
        }
        catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }

    /**
     * Spans are exported in batches, on each service's own schedule, so wait until both sides of every call are in:
     * each caller's client spans and employee-service's server spans, and the RabbitMQ and Kafka deliveries' consumer
     * spans in employee-service and payroll-service.
     */
    private static TraceSource awaitTraces(TraceSource zipkin, Map<String, Integer> expectedCalls) {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(60));
        List<List<TraceSpan>> traces = List.of();
        while (Instant.now().isBefore(deadline)) {
            traces = zipkin.traces(List.of("profile-service", "employee-service", "payroll-service"));
            List<TraceSpan> spans = traces.stream().flatMap(List::stream).toList();
            boolean sent = expectedCalls.entrySet().stream().allMatch(caller ->
                    count(spans, span -> span.isClient() && caller.getKey().equals(span.service())) >= caller.getValue());
            // One more: the admin's salary update.
            boolean received = count(spans, span -> span.isServer() && "employee-service".equals(span.service()))
                    >= expectedCalls.values().stream().mapToInt(Integer::intValue).sum() + 1;
            boolean delivered = count(spans, span -> span.isConsumer() && "employee-service".equals(span.service())) >= 1
                    && count(spans, span -> span.isConsumer() && "payroll-service".equals(span.service())) >= 1;
            if (sent && received && delivered) {
                return ZipkinTraces.of(traces);
            }
            ManagedProcess.sleep(Duration.ofSeconds(2));
        }
        throw new IllegalStateException("Only " + traces.size() + " traces reached Zipkin in time");
    }

    private static long count(List<TraceSpan> spans, Predicate<TraceSpan> matching) {
        return spans.stream().filter(matching).count();
    }

    private static ApplicationGraph scan(String service) {
        return ProjectScans.defaultScanner().scan(ProjectScans.project(SERVICES.resolve(service), null,
                "system-test", List.of()));
    }

    private static Path jar(String service) {
        return SERVICES.resolve(service).resolve("build/libs/" + service + "-0.0.1-SNAPSHOT.jar");
    }

    private static List<String> concat(List<String> base, String... more) {
        List<String> all = new ArrayList<>(base);
        all.addAll(List.of(more));
        return all;
    }
}
