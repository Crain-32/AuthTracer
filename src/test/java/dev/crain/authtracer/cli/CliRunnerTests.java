package dev.crain.authtracer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.sun.net.httpserver.HttpServer;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.IdentityUsage;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class CliRunnerTests {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    /**
     * A trace of front calling back's {@code GET /items/{id}}.
     */
    private static final String TRACE = """
            [[{"traceId": "t1", "id": "1", "kind": "SERVER", "name": "http get /orders",
               "localEndpoint": {"serviceName": "front"}, "tags": {"method": "GET", "uri": "/orders"}},
              {"traceId": "t1", "id": "2", "parentId": "1", "kind": "CLIENT", "name": "http get",
               "localEndpoint": {"serviceName": "front"},
               "tags": {"method": "GET", "uri": "/items/{id}", "http.url": "http://localhost:9001/items/7"}},
              {"traceId": "t1", "id": "3", "parentId": "2", "kind": "SERVER", "name": "http get /items/{id}",
               "localEndpoint": {"serviceName": "back"}, "tags": {"method": "GET", "uri": "/items/{id}"}}]]
            """;

    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"));
    private static final Requirement AUDITOR = Requirement.anyAuthority(List.of("ROLE_AUDITOR"));

    @TempDir
    Path dir;

    @Test
    void aDiffFailsWhenAuthorizationGotWeakerOnly() {
        Path admin = graph("admin.json", ADMIN);

        assertThat(exitCode("diff", "--base", admin.toString(), "--head", graph("open.json",
                Requirement.authenticated()).toString())).isEqualTo(CliRunner.FAILED);
        assertThat(exitCode("diff", "--base", admin.toString(), "--head", admin.toString())).isEqualTo(CliRunner.OK);
        assertThat(exitCode("diff", "--base", graph("open.json", Requirement.authenticated()).toString(), "--head",
                admin.toString())).isEqualTo(CliRunner.OK);
    }

    @Test
    void aChangeThatNeedsReviewFailsOnlyWhenAskedTo() {
        Path admin = graph("admin.json", ADMIN);
        Path auditor = graph("auditor.json", AUDITOR);

        assertThat(exitCode("diff", "--base", admin.toString(), "--head", auditor.toString()))
                .isEqualTo(CliRunner.OK);
        assertThat(exitCode("diff", "--base", admin.toString(), "--head", auditor.toString(), "--fail-on-review",
                "true")).isEqualTo(CliRunner.FAILED);
    }

    @Test
    void policiesFailWhenSomethingIsExposedWithLessThanItsPolicy() {
        ProvidedFact adminOnly = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI", List.of("PCI"),
                "hasRole('ADMIN')", null, ProvidedFact.Origin.ORG);

        assertThat(exitCode("policies", "--graph", graph("open.json", Requirement.authenticated(), adminOnly)
                .toString())).isEqualTo(CliRunner.FAILED);
        assertThat(exitCode("policies", "--graph", graph("admin.json", ADMIN, adminOnly).toString()))
                .isEqualTo(CliRunner.OK);
    }

    @Test
    void anOverScopedIdentityFailsOnlyWhenAskedTo() {
        IdentityUsage overScoped = new IdentityUsage(List.of("SCOPE_read", "SCOPE_write"), "JwtAuthenticationToken", 2,
                List.of("back GET /items"), List.of("SCOPE_read"), List.of("SCOPE_write"), 0, 0);
        Path system = dir.resolve("system.json");
        GraphJson.write(new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(), List.of(), List.of(), List.of(),
                List.of(overScoped), List.of()), system);

        assertThat(exitCode("identities", "--graph", system.toString())).isEqualTo(CliRunner.OK);
        assertThat(exitCode("identities", "--graph", system.toString(), "--fail-on-unneeded", "true"))
                .isEqualTo(CliRunner.FAILED);
    }

    @Test
    void aCommandThatBreaksExitsWithItsOwnCode() throws IOException {
        Path malformed = Files.writeString(dir.resolve("head.json"), "{\"nodes\": [}");
        Path notAGraph = Files.writeString(dir.resolve("other.json"), "{\"name\": \"package.json\"}");
        Path base = graph("base.json", ADMIN);

        // The base is read, the head isn't: an error in a file, not in how the command was called.
        assertThat(exitCode("diff", "--base", base.toString(), "--head", malformed.toString()))
                .isEqualTo(CliRunner.ERROR);
        assertThat(exitCode("exposures", "--graph", malformed.toString())).isEqualTo(CliRunner.ERROR);
        assertThat(exitCode("exposures", "--graph", notAGraph.toString())).isEqualTo(CliRunner.ERROR);
    }

    @Test
    void aFactsFileThatDoesNotExistIsAUsageErrorAndOneThatIsWrongIsAnError() throws IOException {
        assertThat(exitCode("scan", "--classes", dir.toString(), "--service", "app", "--out",
                dir.resolve("out.json").toString(), "--org-facts", dir.resolve("org.yaml").toString()))
                .isEqualTo(CliRunner.USAGE);
        assertThat(exitCode("scan", "--classes", dir.toString(), "--service", "app", "--out",
                dir.resolve("out.json").toString(), "--facts", dir.resolve("authtracer.yaml").toString()))
                .isEqualTo(CliRunner.USAGE);
        Path unknownKind = Files.writeString(dir.resolve("authtracer.yaml"), """
                version: 1
                facts:
                  - kind: trusted
                    field: app.Account.iban
                """);
        assertThat(exitCode("scan", "--classes", dir.toString(), "--service", "app", "--out",
                dir.resolve("out.json").toString(), "--facts", unknownKind.toString())).isEqualTo(CliRunner.ERROR);
    }

    @Test
    void optionsThatAreMissingOrMalformedAreUsageErrors() {
        Path base = graph("base.json", ADMIN);

        assertThat(exitCode("diff", "--head", base.toString())).isEqualTo(CliRunner.USAGE);
        assertThat(exitCode("diff", "--base", base.toString(), "--head", base.toString(), "--sources", "employee-service"))
                .isEqualTo(CliRunner.USAGE);
        assertThat(exitCode("link", "--graphs", base.toString(), "--zipkin", "http://localhost:9411", "--lookback",
                "an-hour", "--out", dir.resolve("system.json").toString())).isEqualTo(CliRunner.USAGE);
        assertThat(exitCode("link", "--graphs", " , ", "--out", dir.resolve("system.json").toString()))
                .isEqualTo(CliRunner.USAGE);
        assertThat(dir.resolve("system.json")).doesNotExist();
        assertThat(exitCode("scan", "--project", dir.resolve("missing").toString(), "--out",
                dir.resolve("out.json").toString())).isEqualTo(CliRunner.USAGE);
        assertThat(exitCode("verify")).isEqualTo(CliRunner.USAGE);
    }

    /**
     * A mistyped option, or a gate's flag that isn't true or false, would otherwise switch something off quietly: no
     * Org policies for {@code --org-fact}, no failing on review for {@code --fail-on-review yes}.
     */
    @Test
    void anOptionTheCommandDoesntTakeOrAFlagThatIsntTrueOrFalseIsAUsageError() {
        Path admin = graph("admin.json", ADMIN);
        Path auditor = graph("auditor.json", AUDITOR);

        assertThat(exitCode("scan", "--classes", dir.toString(), "--service", "app", "--out",
                dir.resolve("out.json").toString(), "--org-fact", admin.toString())).isEqualTo(CliRunner.USAGE);
        assertThat(dir.resolve("out.json")).doesNotExist();
        assertThat(exitCode("diff", "--base", admin.toString(), "--head", auditor.toString(), "--fail-on-review",
                "yes")).isEqualTo(CliRunner.USAGE);
        assertThat(exitCode("diff", "--base", admin.toString(), "--head", auditor.toString(), "--fail-on-review",
                "false")).isEqualTo(CliRunner.OK);
        assertThat(exitCode("exposures", "--graph", admin.toString(), "--fail-on-review")).isEqualTo(CliRunner.USAGE);
    }

    /**
     * A class directory or library that isn't there would leave a graph of nothing, which diffs as every endpoint
     * removed.
     */
    @Test
    void classesOrLibrariesThatArentThereAreAUsageError() {
        assertThat(exitCode("scan", "--classes", dir.resolve("build/clases").toString(), "--service", "app", "--out",
                dir.resolve("out.json").toString())).isEqualTo(CliRunner.USAGE);
        assertThat(exitCode("scan", "--classes", dir.toString(), "--libraries", dir.resolve("lib.jar").toString(),
                "--service", "app", "--out", dir.resolve("out.json").toString())).isEqualTo(CliRunner.USAGE);
        assertThat(dir.resolve("out.json")).doesNotExist();
    }

    /**
     * Decision 0080's "shown, never guessed" for the whole scan: a scan that read no classes says so in the graph, so
     * the diff shows it for review rather than a service whose endpoints all went away.
     */
    @Test
    void aScanThatReadNoClassesSaysSoInTheGraph() throws IOException {
        Path empty = Files.createDirectories(dir.resolve("empty"));

        assertThat(exitCode("scan", "--classes", empty.toString(), "--service", "app", "--out",
                dir.resolve("out.json").toString())).isEqualTo(CliRunner.OK);
        assertThat(GraphJson.read(dir.resolve("out.json")).findings()).singleElement()
                .satisfies(finding -> assertThat(finding.message()).startsWith("No application classes were read"));
    }

    @Test
    void aGraphThatCantBePublishedIsAnErrorNotAVerdict() throws IOException {
        Path classes = Files.createDirectories(dir.resolve("classes"));
        int closed;
        try (ServerSocket socket = new ServerSocket(0)) {
            closed = socket.getLocalPort();
        }
        assertThat(exitCode("scan", "--classes", classes.toString(), "--service", "app", "--out",
                dir.resolve("out.json").toString(), "--publish", "http://localhost:" + closed))
                .isEqualTo(CliRunner.ERROR);

        HttpServer refusing = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        refusing.createContext("/api/graphs", exchange -> {
            exchange.sendResponseHeaders(400, -1);
            exchange.close();
        });
        refusing.start();
        try {
            assertThat(exitCode("scan", "--classes", classes.toString(), "--service", "app", "--out",
                    dir.resolve("out.json").toString(), "--publish", "http://localhost:"
                            + refusing.getAddress().getPort())).isEqualTo(CliRunner.ERROR);
        }
        finally {
            refusing.stop(0);
        }
    }

    @Test
    void aScannedGraphIsWrittenAndPublishedUnderTheServersPath() throws IOException {
        Path classes = Files.createDirectories(dir.resolve("classes"));
        Path out = dir.resolve("graphs/app.json");
        assertThat(exitCode("scan", "--classes", classes.toString(), "--service", "app", "--revision", "r3", "--out",
                out.toString())).isEqualTo(CliRunner.OK);
        assertThat(GraphJson.read(out)).satisfies(graph -> {
            assertThat(graph.service()).isEqualTo("app");
            assertThat(graph.revision()).isEqualTo("r3");
        });

        List<String> received = new ArrayList<>();
        HttpServer authTracer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        authTracer.createContext("/authtracer/api/graphs", exchange -> {
            received.add(exchange.getRequestMethod() + " " + exchange.getRequestHeaders().getFirst("Content-Type"));
            received.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(201, -1);
            exchange.close();
        });
        authTracer.start();
        try {
            assertThat(exitCode("scan", "--classes", classes.toString(), "--service", "app", "--out", out.toString(),
                    "--publish", "http://localhost:" + authTracer.getAddress().getPort() + "/authtracer/"))
                    .isEqualTo(CliRunner.OK);
        }
        finally {
            authTracer.stop(0);
        }
        assertThat(received).hasSize(2).first().isEqualTo("POST application/json");
        assertThat(GraphJson.read(received.get(1)).service()).isEqualTo("app");
    }

    @Test
    void linkJoinsTheGraphsAndATracesFileConfirmsTheLink() throws IOException {
        String graphs = linkedGraphs();
        Path system = dir.resolve("system.json");

        assertThat(exitCode("link", "--graphs", graphs, "--out", system.toString())).isEqualTo(CliRunner.OK);
        assertThat(GraphJson.readAny(system).services()).extracting(ApplicationGraph::service)
                .containsExactly("back", "front");
        assertThat(GraphJson.readAny(system).links()).singleElement().extracting(Edge::kind)
                .isEqualTo(Edge.Kind.NETWORK_INFERRED);

        Path traces = Files.writeString(dir.resolve("traces.json"), TRACE);
        assertThat(exitCode("link", "--graphs", graphs, "--traces", traces.toString(), "--out", system.toString()))
                .isEqualTo(CliRunner.OK);
        assertThat(GraphJson.readAny(system).links()).singleElement().extracting(Edge::kind)
                .isEqualTo(Edge.Kind.NETWORK_OBSERVED);
    }

    @Test
    void linkReadsZipkinAsFarBackAsItIsTold() throws IOException {
        String graphs = linkedGraphs();
        Path system = dir.resolve("system.json");
        List<String> queries = new ArrayList<>();
        HttpServer zipkin = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        zipkin.createContext("/api/v2/traces", exchange -> {
            queries.add(exchange.getRequestURI().getQuery());
            byte[] body = TRACE.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        zipkin.start();
        try {
            assertThat(exitCode("link", "--graphs", graphs, "--zipkin", "http://localhost:"
                    + zipkin.getAddress().getPort(), "--lookback", "5", "--out", system.toString()))
                    .isEqualTo(CliRunner.OK);
        }
        finally {
            zipkin.stop(0);
        }
        // Minutes on the command line, milliseconds to Zipkin.
        assertThat(queries).containsExactly("serviceName=front&lookback=300000&limit=1000",
                "serviceName=back&lookback=300000&limit=1000");
        assertThat(GraphJson.readAny(system).links()).singleElement().extracting(Edge::kind)
                .isEqualTo(Edge.Kind.NETWORK_OBSERVED);
    }

    @Test
    void exposuresListWhatEachEndpointGivesAndWhatACallerNeeds() throws IOException {
        Path graph = graph("bank.json", ADMIN);
        Path out = dir.resolve("exposures.md");
        String header = "| Service | Endpoint | Field | Requirement | Checks | Sources |";
        String endpoint = "| bank | `GET /accounts/{id}` | (endpoint) | ROLE_ADMIN | @PreAuthorize |  |";
        String iban = "| bank | `GET /accounts/{id}` | `iban` | ROLE_ADMIN | @PreAuthorize | bank:Account.iban |";

        assertThat(exitCode("exposures", "--graph", graph.toString(), "--out", out.toString()))
                .isEqualTo(CliRunner.OK);
        assertThat(Files.readAllLines(out)).containsExactly(header, "|---|---|---|---|---|---|", endpoint, iban);

        // A field by its name, or by where it comes from.
        assertThat(exitCode("exposures", "--graph", graph.toString(), "--field", "iban", "--out", out.toString()))
                .isEqualTo(CliRunner.OK);
        assertThat(Files.readAllLines(out)).hasSize(3).last().isEqualTo(iban);
        assertThat(exitCode("exposures", "--graph", graph.toString(), "--field", "Account", "--out",
                out.toString())).isEqualTo(CliRunner.OK);
        assertThat(Files.readAllLines(out)).hasSize(3).last().isEqualTo(iban);
        assertThat(exitCode("exposures", "--graph", graph.toString(), "--field", "pin", "--out", out.toString()))
                .isEqualTo(CliRunner.OK);
        assertThat(Files.readAllLines(out)).hasSize(2);
    }

    @Test
    void aDiffWritesEachReportItIsAskedFor() throws IOException {
        Path admin = graph("admin.json", ADMIN);
        Path open = graph("open.json", Requirement.authenticated());
        Path project = dir.resolve("bank");
        Path source = project.resolve("src/main/java/app/Accounts.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, """
                package app;

                class Accounts {

                    @PreAuthorize("hasRole('ADMIN')")
                    Account get(long id) {
                        return null;
                    }
                }
                """);
        Path report = dir.resolve("out/diff.md");
        Path json = dir.resolve("out/diff.json");
        Path sarif = dir.resolve("out/diff.sarif");
        Path agent = dir.resolve("out/agent.md");

        assertThat(exitCode("diff", "--base", admin.toString(), "--head", open.toString(), "--report",
                report.toString(), "--json", json.toString(), "--sarif", sarif.toString(), "--sources",
                "bank=" + project, "--agent-report", agent.toString())).isEqualTo(CliRunner.FAILED);

        assertThat(Files.readString(report)).startsWith("# AuthTracer diff")
                .contains("| FAIL | WEAKENED | bank | `GET /accounts/{id}` | (endpoint) | ROLE_ADMIN | authenticated |");
        // The endpoint, and the field it returns.
        JsonNode changes = JSON.readTree(Files.readString(json)).get("changes");
        assertThat(changes.valueStream().map(change -> change.get("kind").asString() + " "
                + change.path("field").asString(""))).containsExactly("WEAKENED ", "WEAKENED iban");
        JsonNode location = JSON.readTree(Files.readString(sarif)).at("/runs/0/results/0/locations/0/physicalLocation");
        assertThat(location.at("/artifactLocation/uri").asString()).isEqualTo("src/main/java/app/Accounts.java");
        assertThat(location.at("/region/startLine").asInt()).isEqualTo(5);
        assertThat(Files.readString(agent)).contains("src/main/java/app/Accounts.java:5");

        // Nothing weaker: the agent is told so.
        assertThat(exitCode("diff", "--base", admin.toString(), "--head", admin.toString(), "--agent-report",
                agent.toString())).isEqualTo(CliRunner.OK);
        assertThat(Files.readString(agent)).isEqualTo("AuthTracer: no authorization got weaker.\n");
    }

    @Test
    void aReportThatCantBeWrittenIsAnError() throws IOException {
        Path admin = graph("admin.json", ADMIN);
        Path file = Files.writeString(dir.resolve("taken"), "a file, not a directory");

        assertThat(exitCode("diff", "--base", admin.toString(), "--head", admin.toString(), "--report",
                file.resolve("diff.md").toString())).isEqualTo(CliRunner.ERROR);
        assertThat(exitCode("exposures", "--graph", dir.resolve("missing.json").toString()))
                .isEqualTo(CliRunner.ERROR);
    }

    @Test
    void aPolicyViolationIsListedWithThePolicysReason() throws IOException {
        ProvidedFact adminOnly = new ProvidedFact(ProvidedFact.Kind.POLICY, "PCI", List.of("PCI"),
                "hasRole('ADMIN')", "card data", ProvidedFact.Origin.ORG);
        Path out = dir.resolve("policies.md");

        assertThat(exitCode("policies", "--graph", graph("open.json", Requirement.authenticated(), adminOnly)
                .toString(), "--out", out.toString())).isEqualTo(CliRunner.FAILED);
        assertThat(Files.readAllLines(out)).last()
                .isEqualTo("| bank | `GET /accounts/{id}` | `iban` | PCI (card data) | ROLE_ADMIN | authenticated |");
    }

    @Test
    void identitiesThatNeededAllTheyHoldPassEvenWhenAskedToFail() throws IOException {
        IdentityUsage exact = new IdentityUsage(List.of("SCOPE_read"), "JwtAuthenticationToken", 3,
                List.of("back GET /items"), List.of("SCOPE_read"), List.of(), 1, 2);
        Path system = dir.resolve("system.json");
        GraphJson.write(new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(), List.of(), List.of(), List.of(),
                List.of(exact), List.of()), system);
        Path out = dir.resolve("identities.md");

        assertThat(exitCode("identities", "--graph", system.toString(), "--fail-on-unneeded", "true", "--out",
                out.toString())).isEqualTo(CliRunner.OK);
        assertThat(Files.readAllLines(out)).last().isEqualTo("| 1 | JwtAuthenticationToken | 3 | SCOPE_read |  | 1 | 2 |");
    }

    /**
     * Front, on 9000, calls {@code GET /items/{id}} on back, on 9001: the graphs' files, as {@code --graphs} takes them.
     */
    private String linkedGraphs() {
        Egress call = Egress.of("RestClient", "GET", "/items/{id}", "http://localhost:9001", null,
                CodeRef.ofMethod("front.Client", "get(long)"), null);
        Ingress items = Ingress.of("GET", "/items/{id}", CodeRef.ofMethod("back.Items", "get(long)"));
        Path front = dir.resolve("front.json");
        Path back = dir.resolve("back.json");
        GraphJson.write(new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "front", "r1", 9000,
                AuthoritySource.UNKNOWN, List.of(call), List.of(), List.of(), List.of(), List.of()), front);
        GraphJson.write(new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "back", "r1", 9001,
                AuthoritySource.UNKNOWN, List.of(items), List.of(), List.of(), List.of(), List.of()), back);
        return front + "," + back;
    }

    /**
     * One endpoint returning an Account whose iban is labelled PCI, behind one method check.
     */
    private Path graph(String name, Requirement requirement, ProvidedFact... facts) {
        Ingress ingress = Ingress.of("GET", "/accounts/{id}", CodeRef.ofMethod("app.Accounts", "get(long)"))
                .withResponse(new Payload("app.Account", false));
        AuthorizationLocation check = new AuthorizationLocation("location:METHOD:app.Accounts#get", "@PreAuthorize",
                AuthorizationLocation.Scope.METHOD, AuthorizationLocation.Phase.PRE, requirement,
                CodeRef.ofMethod("app.Accounts", "get(long)"), null, null, AuthorizationLocation.Denial.THROW, true);
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "bank", name, 8080,
                AuthoritySource.UNKNOWN, List.of(ingress, check,
                        Field.of("app.Account", "iban", "iban", "java.lang.String").withLabels(List.of("PCI"))),
                List.of(Edge.local(ingress.id(), ingress.id(), check.id(), 1, List.of())), List.of(),
                List.of(facts), List.of());
        Path file = dir.resolve(name);
        GraphJson.write(graph, file);
        return file;
    }

    private static int exitCode(String... args) {
        CliRunner runner = new CliRunner();
        runner.run(new DefaultApplicationArguments(args));
        return runner.getExitCode();
    }
}
