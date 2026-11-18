package dev.crain.authtracer;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;

/**
 * Links the golden graphs with traces recorded from the running example services.
 */
class ExampleServicesLinkTests {

    private static final Path GOLDEN = Path.of(System.getProperty("authtracer.golden.dir"));

    @Test
    void everyRuntimeCheckMatchesTheStaticGraph() throws URISyntaxException {
        Path traces = Path.of(getClass().getResource("/zipkin/example-services-traces.json").toURI());
        List<ApplicationGraph> graphs = List.of(GraphJson.read(GOLDEN.resolve("profile-service.json")),
                GraphJson.read(GOLDEN.resolve("employee-service.json")), GraphJson.read(GOLDEN.resolve("payroll-service.json")));

        SystemGraph system = new Linker().link(graphs, ZipkinTraces.file(traces));

        // REST, GraphQL and gRPC calls, a Kafka send and a RabbitMQ send: the traces confirm each one.
        assertThat(system.links()).extracting(Edge::from, Edge::to, Edge::kind).containsExactlyInAnyOrder(
                observed("profile-service/egress:dev.crain.profileservice.employeeservice.EmployeeServiceClient"
                        + "#getEmployee(long) GET /employees/{id}", "employee-service/ingress:GET /employees/{id}"),
                observed("profile-service/egress:dev.crain.profileservice.employeeservice.EmployeeGraphQlClient"
                        + "#employee(long) QUERY employee", "employee-service/ingress:QUERY employee"),
                observed("profile-service/egress:dev.crain.profileservice.employeeservice.EmployeeGraphQlClient"
                        + "#employees() QUERY employees", "employee-service/ingress:QUERY employees"),
                observed("payroll-service/egress:dev.crain.payrollservice.employeeservice.EmployeeServiceClient"
                        + "#employee(long) GRPC employees.v1.EmployeeDirectory/GetEmployee",
                        "employee-service/ingress:GRPC employees.v1.EmployeeDirectory/GetEmployee"),
                // The Kafka listener's call, with payroll-service's own token.
                observed("payroll-service/egress:dev.crain.payrollservice.employeeservice.EmployeeServiceClient"
                        + "#employeeAsPayroll(long) GRPC employees.v1.EmployeeDirectory/GetEmployee",
                        "employee-service/ingress:GRPC employees.v1.EmployeeDirectory/GetEmployee"),
                observed("employee-service/egress:dev.crain.employeeservice.employee.SalaryChanges"
                        + "#publish(long,java.math.BigDecimal,java.math.BigDecimal,java.lang.String) KAFKA employee.salary-changed",
                        "payroll-service/ingress:KAFKA employee.salary-changed"),
                observed("profile-service/egress:dev.crain.profileservice.audit.CompensationAudit"
                        + "#viewed(long,java.lang.String) RABBIT audit.compensation-viewed",
                        "employee-service/ingress:RABBIT audit.compensation-viewed"));
        // Decision 0021: employee-service's checks on that call evaluate payroll-service, not the listener's callers.
        assertThat(system.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.BYPASSED);
            assertThat(finding.message()).isEqualTo("payroll-service calls employee-service GRPC"
                    + " employees.v1.EmployeeDirectory/GetEmployee with its own OAuth2 client token"
                    + " (BearerTokenAuthenticationInterceptor: an authorized client's token, from"
                    + " EmployeeServiceClient#employeeAsPayroll): the checks there (authorizeRequests (gRPC),"
                    + " @PreAuthorize, field check on salary) evaluate payroll-service, not its callers, so they don't"
                    + " count toward what payroll-service's callers need");
        });
        assertThat(system.flows()).anySatisfy(flow -> {
            assertThat(flow.from()).isEqualTo("employee-service/field:dev.crain.employeeservice.employee.Employee.ssn");
            assertThat(flow.to()).isEqualTo("profile-service/field:dev.crain.profileservice.employeeservice.EmployeeDto.ssn");
        });
        assertThat(system.flows()).anySatisfy(flow -> {
            assertThat(flow.from()).isEqualTo("employee-service/field:dev.crain.employees.v1.EmployeeRecord.salary");
            assertThat(flow.to()).isEqualTo("payroll-service/field:dev.crain.employees.v1.EmployeeRecord.salary");
        });
        assertThat(system.observation(
                "employee-service/location:FIELD:dev.crain.employeeservice.employee.Employee#getSsn():@PreAuthorize"))
                .hasValueSatisfying(observation -> {
                    assertThat(observation.granted()).isPositive();
                    assertThat(observation.denied()).isPositive();
                });
    }

    private static org.assertj.core.groups.Tuple observed(String from, String to) {
        return org.assertj.core.groups.Tuple.tuple(from, to, Edge.Kind.NETWORK_OBSERVED);
    }

    @Test
    void testUsersHoldScopesTheirRequestsNeverNeeded() throws URISyntaxException {
        Path traces = Path.of(getClass().getResource("/zipkin/example-services-traces.json").toURI());
        List<ApplicationGraph> graphs = List.of(GraphJson.read(GOLDEN.resolve("profile-service.json")),
                GraphJson.read(GOLDEN.resolve("employee-service.json")));

        SystemGraph system = new Linker().link(graphs, ZipkinTraces.file(traces));

        // identity-service's users: admin, an auditor, and plain users. Each token holds openid/profile and the write scope.
        assertThat(system.identities()).filteredOn(identity -> identity.authorities().contains("SCOPE_openid"))
                .hasSize(3).allSatisfy(identity -> {
            assertThat(identity.authorities()).contains("SCOPE_employees.read", "SCOPE_employees.write")
                    .noneMatch(authority -> authority.startsWith("FACTOR_"));
            assertThat(identity.needed()).contains("SCOPE_employees.read");
            assertThat(identity.unneeded()).contains("SCOPE_openid", "SCOPE_profile", "SCOPE_employees.write");
            assertThat(identity.unread()).isZero();
        });
        assertThat(system.identities()).filteredOn(identity -> identity.authorities().contains("ROLE_ADMIN"))
                .singleElement().satisfies(admin -> {
                    // The salary update asks for ROLE_ADMIN only, so the write scope is never needed.
                    assertThat(admin.endpoints()).contains("employee-service PUT /admin/employees/{id}/salary");
                    assertThat(admin.needed()).containsExactly("ROLE_ADMIN", "SCOPE_employees.read");
                });
        // payroll-service's own token (client credentials) holds the one scope its client is registered for, and
        // needs it; the salary's field check denies it, as it has no role.
        assertThat(system.identities()).filteredOn(identity -> !identity.authorities().contains("SCOPE_openid"))
                .singleElement().satisfies(service -> {
                    assertThat(service.authorities()).containsExactly("SCOPE_employees.read");
                    assertThat(service.needed()).containsExactly("SCOPE_employees.read");
                    assertThat(service.unneeded()).isEmpty();
                    assertThat(service.endpoints()).containsExactly(
                            "employee-service GRPC employees.v1.EmployeeDirectory/GetEmployee");
                    assertThat(service.denied()).isPositive();
                });
    }

    @Test
    void payrollServicesOwnTokenCarriesWhatTheDirectoryAsks() {
        List<ApplicationGraph> graphs = List.of(GraphJson.read(GOLDEN.resolve("employee-service.json")),
                GraphJson.read(GOLDEN.resolve("payroll-service.json")),
                GraphJson.read(GOLDEN.resolve("identity-service.json")));
        SystemGraph system = new Linker().link(graphs, ZipkinTraces.of(List.of()));

        // Decision 0075 amended: its registration asks identity-service for employees.read as client
        // payroll-service, which identity-service grants it, and employee-service's checks on the call ask for no
        // other scope.
        Egress call = system.services().stream().filter(graph -> graph.service().equals("payroll-service"))
                .flatMap(graph -> graph.nodes(Egress.class).stream())
                .filter(egress -> egress.registration() != null).findFirst().orElseThrow();
        assertThat(call.registration().clientId()).isEqualTo("payroll-service");
        assertThat(call.registration().scopes()).containsExactly("employees.read");
        assertThat(system.links()).extracting(Edge::from, Edge::to).contains(org.assertj.core.groups.Tuple.tuple(
                "payroll-service/egress:org.springframework.security.oauth2.client.registration.ClientRegistration"
                        + " POST /oauth2/token", "identity-service/ingress:POST /oauth2/token"));
        assertThat(system.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.TOKEN_REJECTED
                || finding.kind() == Finding.Kind.ALWAYS_DENIED);
        // The name the listener keeps comes from employee-service's employee, over the call made with that token.
        Exposure name = Exposures.of(system).stream()
                .filter(exposure -> exposure.endpoint().equals("GET /payroll/changes")
                        && exposure.field().equals("employeeName"))
                .findFirst().orElseThrow();
        assertThat(name.sources()).containsExactlyInAnyOrder(
                "employee-service/field:dev.crain.employeeservice.employee.Employee.firstName",
                "employee-service/field:dev.crain.employeeservice.employee.Employee.lastName");
        assertThat(name.lineage()).filteredOn(flow -> flow.kind() == Flow.Kind.NETWORK).extracting(Flow::path)
                .containsOnly("payroll-service/" + call.id());
        // Its checks there evaluate payroll-service: the readers of /payroll/changes need only ROLE_ADMIN.
        assertThat(name.requirement()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    void ssnLast4InProfileServiceComesFromEmployeeServicesAdminOnlyField() {
        List<ApplicationGraph> graphs = List.of(GraphJson.read(GOLDEN.resolve("profile-service.json")),
                GraphJson.read(GOLDEN.resolve("employee-service.json")));
        SystemGraph system = new Linker().link(graphs, ZipkinTraces.of(List.of()));

        Exposure ssnLast4 = Exposures.of(system).stream()
                .filter(exposure -> exposure.endpoint().equals("GET /profiles/{id}")
                        && exposure.field().equals("ssnLast4"))
                .findFirst().orElseThrow();

        assertThat(ssnLast4.requirement()).isEqualTo("SCOPE_employees.read and ROLE_ADMIN");
        assertThat(ssnLast4.sources()).containsExactly("employee-service/field:dev.crain.employeeservice.employee.Employee.ssn");
        assertThat(ssnLast4.lineage()).extracting(Flow::to, Flow::source, Flow::kind).containsExactly(
                org.assertj.core.groups.Tuple.tuple(
                        "profile-service/field:dev.crain.profileservice.profile.ProfileView.ssnLast4", FieldSource.COMPUTED,
                        Flow.Kind.LOCAL),
                org.assertj.core.groups.Tuple.tuple("profile-service/field:dev.crain.profileservice.employeeservice.EmployeeDto.ssn",
                        FieldSource.DIRECT, Flow.Kind.NETWORK));
        // The GraphQL query answers with employee-service's Employee itself: ssn comes straight from it.
        assertThat(ssnLast4.lineage()).last().extracting(Flow::from)
                .isEqualTo("employee-service/field:dev.crain.employeeservice.employee.Employee.ssn");
    }

    @Test
    void theCompensationViewsEmployeeServiceServesComeFromProfileServicesAuditEvents() {
        List<ApplicationGraph> graphs = List.of(GraphJson.read(GOLDEN.resolve("profile-service.json")),
                GraphJson.read(GOLDEN.resolve("employee-service.json")));
        SystemGraph system = new Linker().link(graphs, ZipkinTraces.of(List.of()));

        // Decision 0098: the listener writes each event into a CompensationView, which the audit endpoint serves.
        Exposure viewedBy = Exposures.of(system).stream()
                .filter(exposure -> exposure.endpoint().equals("GET /audit/employees/{id}/views")
                        && exposure.field().equals("viewedBy"))
                .findFirst().orElseThrow();
        assertThat(viewedBy.sources()).containsExactly(
                "profile-service/field:dev.crain.profileservice.audit.CompensationAudit$CompensationViewed.viewedBy");
        assertThat(viewedBy.lineage()).extracting(Flow::path, Flow::kind).containsExactly(
                org.assertj.core.groups.Tuple.tuple("employee-service/ingress:RABBIT audit.compensation-viewed",
                        Flow.Kind.LOCAL),
                org.assertj.core.groups.Tuple.tuple("profile-service/egress:dev.crain.profileservice.audit"
                        + ".CompensationAudit#viewed(long,java.lang.String) RABBIT audit.compensation-viewed",
                        Flow.Kind.NETWORK));
    }

    @Test
    void theResourceServersCheckTokensWithIdentityService() {
        List<ApplicationGraph> graphs = List.of(GraphJson.read(GOLDEN.resolve("profile-service.json")),
                GraphJson.read(GOLDEN.resolve("employee-service.json")), GraphJson.read(GOLDEN.resolve("payroll-service.json")),
                GraphJson.read(GOLDEN.resolve("identity-service.json")));
        SystemGraph system = new Linker().link(graphs, ZipkinTraces.of(List.of()));

        // Their issuer-uri is identity-service's: each fetches its OpenID configuration, which names the JWK set.
        // payroll-service also gets its own tokens from identity-service's token endpoint.
        assertThat(system.links()).filteredOn(link -> link.to().startsWith("identity-service/"))
                .extracting(link -> SystemGraph.serviceOf(link.from()), Edge::to).containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple("profile-service",
                                "identity-service/ingress:GET /.well-known/openid-configuration"),
                        org.assertj.core.groups.Tuple.tuple("employee-service",
                                "identity-service/ingress:GET /.well-known/openid-configuration"),
                        org.assertj.core.groups.Tuple.tuple("payroll-service",
                                "identity-service/ingress:GET /.well-known/openid-configuration"),
                        org.assertj.core.groups.Tuple.tuple("payroll-service",
                                "identity-service/ingress:POST /oauth2/token"));
        // Not on a request path, those calls act for no caller.
        assertThat(system.findings()).noneMatch(finding -> finding.message().contains("identity-service"));
    }
}
