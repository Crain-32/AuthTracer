package dev.crain.authtracer.graph;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

@ExtendWith(OutputCaptureExtension.class)
class GraphJsonTests {

    @Test
    void roundTripsAndSerializesStably() {
        CodeRef handler = CodeRef.ofMethod("com.example.Controller", "get(long)");
        Ingress ingress = Ingress.of("GET", "/things/{id}", handler);
        AuthorizationLocation check = new AuthorizationLocation("location:METHOD:com.example.Service#get(long)",
                "@PreAuthorize", AuthorizationLocation.Scope.METHOD, AuthorizationLocation.Phase.PRE,
                Requirement.or(List.of(Requirement.anyAuthority(List.of("ROLE_ADMIN")),
                        Requirement.expression("filterObject.owner == authentication.name"))),
                CodeRef.ofMethod("com.example.Service", "get(long)"), null, null,
                AuthorizationLocation.Denial.THROW, true);
        Egress egress = Egress.of("RestClient", "GET", "/remote/{id}", "http://remote", null, handler.atLine(12),
                new Payload("com.example.RemoteDto", true));
        Field remote = Field.of("com.example.RemoteDto", "name", "name", "java.lang.String");
        Field exposed = Field.of("com.example.View", "label", "display_label", "java.lang.String");
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "things", "abc123", 8080,
                new AuthoritySource(AuthoritySource.Kind.JWT_CLAIMS, AuthoritySource.Freshness.SNAPSHOT, "jwt")
                        .withRoleHierarchy(new TreeMap<>(Map.of("ROLE_ADMIN", new TreeSet<>(Set.of("ROLE_USER"))))),
                List.of(egress, check, ingress.withResponse(new Payload("com.example.View", false)), remote, exposed),
                List.of(Edge.local(ingress.id(), check.id(), egress.id(), 2, List.of("a", "b")),
                        Edge.local(ingress.id(), ingress.id(), check.id(), 1, List.of("a"))),
                List.of(Flow.local(ingress.id(), remote.id(), exposed.id(), FieldSource.COMPUTED)),
                List.of(new ProvidedFact(ProvidedFact.Kind.SENSITIVE, remote.id(), List.of("PII"), null, "test",
                        ProvidedFact.Origin.LOCAL)),
                List.of(new Finding(Finding.Kind.NOT_ENFORCED, "never runs", handler)));

        String json = GraphJson.write(graph);
        ApplicationGraph read = GraphJson.read(json);

        assertThat(read).isEqualTo(graph);
        assertThat(GraphJson.write(read)).isEqualTo(json);
        assertThat(read.path(ingress.id())).extracting(Edge::to).containsExactly(check.id(), egress.id());
        assertThat(json).contains("\"type\" : \"location\"").doesNotContain("\"field\" :");
    }

    @Test
    void whatAResourceServersTokensGrantRoundTrips() {
        AuthoritySource source = new AuthoritySource(AuthoritySource.Kind.JWT_CLAIMS, AuthoritySource.Freshness.SNAPSHOT,
                "jwt", null, new TreeSet<>(Set.of("FACTOR_BEARER", "SCOPE_*")), new AuthoritySource.Jwt(
                        List.of(new AuthoritySource.ClaimAuthorities(List.of("scope", "scp"), null, "SCOPE_", null)),
                        new TreeSet<>(Set.of("orders")), null, null, null));
        ApplicationGraph graph = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "orders", "r1", null, source,
                List.of(), List.of(), List.of(), List.of(), List.of());

        String json = GraphJson.write(graph);

        assertThat(GraphJson.read(json).authoritySource()).isEqualTo(source);
        assertThat(json).doesNotContain("validators").doesNotContain("delimiter");
        assertThat(source.mayGrant("SCOPE_orders.read")).isTrue();
        assertThat(source.mayGrant("FACTOR_BEARER")).isTrue();
        assertThat(source.mayGrant("ROLE_ADMIN")).isFalse();
        assertThat(source.jwt().checksAudience()).isTrue();
        assertThat(AuthoritySource.UNKNOWN.mayGrant("ROLE_ADMIN")).isTrue();
    }

    @Test
    void readsGraphsWrittenBeforeNewerProperties() {
        String old = """
                {"schemaVersion": 1, "service": "old", "revision": "r0",
                 "authoritySource": {"kind": "UNKNOWN", "freshness": "UNKNOWN"},
                 "nodes": [{"type": "field", "id": "field:a.B.c", "owner": "a.B", "name": "c", "jsonName": "c",
                            "javaType": "java.lang.String"}],
                 "edges": [], "flows": [], "findings": [], "futureProperty": true}
                """;

        ApplicationGraph graph = GraphJson.read(old);

        assertThat(graph.nodes(Field.class)).singleElement().satisfies(field -> {
            assertThat(field.declassified()).isFalse();
            assertThat(field.labels()).isEmpty();
        });
        assertThat(graph.provided()).isEmpty();
    }

    @Test
    void aGraphOfANewerSchemaIsReadAndSaidToBe(CapturedOutput output) {
        ApplicationGraph graph = GraphJson.read("""
                {"schemaVersion": 99, "service": "next", "revision": "r9",
                 "authoritySource": {"kind": "UNKNOWN", "freshness": "UNKNOWN"}}
                """);

        assertThat(graph.service()).isEqualTo("next");
        assertThat(output).contains("The graph of next has schema version 99, newer than this AuthTracer's 1");
    }

    @Test
    void aGraphThatLeavesAListOutHasNone() {
        ApplicationGraph graph = GraphJson.read("""
                {"schemaVersion": 1, "service": "old", "revision": "r0",
                 "authoritySource": {"kind": "UNKNOWN", "freshness": "UNKNOWN"}}
                """);
        assertThat(graph.nodes()).isEmpty();
        assertThat(graph.edges()).isEmpty();
        assertThat(graph.flows()).isEmpty();
        assertThat(graph.provided()).isEmpty();
        assertThat(graph.findings()).isEmpty();
        assertThat(graph.additionalPorts()).isEmpty();

        SystemGraph system = GraphJson.readSystem("""
                {"schemaVersion": 1}
                """);
        assertThat(system.services()).isEmpty();
        assertThat(system.links()).isEmpty();
        assertThat(system.flows()).isEmpty();
        assertThat(system.observations()).isEmpty();
        assertThat(system.identities()).isEmpty();
        assertThat(system.findings()).isEmpty();
        // Each list on its own, with the others there.
        assertThat(GraphJson.readSystem("""
                {"schemaVersion": 1, "services": [], "flows": [], "observations": [], "findings": []}
                """).links()).isEmpty();
        assertThat(GraphJson.readSystem("""
                {"schemaVersion": 1, "links": [], "flows": [], "observations": [], "findings": []}
                """).services()).isEmpty();
        assertThat(GraphJson.read("""
                {"schemaVersion": 1, "service": "old", "revision": "r0",
                 "authoritySource": {"kind": "UNKNOWN", "freshness": "UNKNOWN"}, "edges": [], "findings": []}
                """).nodes()).isEmpty();
    }
}
