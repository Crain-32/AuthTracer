package dev.crain.authtracer.api;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Opaque;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import org.junit.jupiter.api.Test;

/**
 * What a graph posted to the server must have for linking and exposures to read it: every part each of them reads.
 */
class GraphValidationTests {

    private static final CodeRef HANDLER = CodeRef.ofMethod("app.Items", "list()");
    private static final Ingress ITEMS = Ingress.of("GET", "/items", HANDLER);

    @Test
    void aGraphWithEveryKindOfNodeWellFormedIsKept() {
        AuthorizationLocation check = location(AuthorizationLocation.Scope.METHOD, Requirement.and(List.of(
                Requirement.authenticated(), Requirement.not(Requirement.anyAuthority(List.of("ROLE_GUEST"))))));
        Egress call = Egress.of("RestClient", "GET", "/stock", "http://stock", null, HANDLER, null);
        ApplicationGraph graph = graph(List.of(ITEMS, check, call, Field.of("app.Item", "name", "name",
                "java.lang.String"), new Opaque("opaque:app.Items#list()", "reflection", HANDLER)),
                List.of(Edge.local(ITEMS.id(), ITEMS.id(), check.id(), 1, List.of())),
                List.of(new ProvidedFact(ProvidedFact.Kind.SENSITIVE, "field:app.Item.name", List.of("PII"), null,
                        null, ProvidedFact.Origin.ORG)));
        Edge link = new Edge("items/" + call.id(), "stock/ingress:GET /stock", Edge.Kind.NETWORK_INFERRED, null, 0,
                List.of(), true);
        Flow carried = new Flow("items/" + call.id(), "stock/field:app.Stock.name", "items/field:app.Item.name",
                FieldSource.DIRECT, Flow.Kind.NETWORK);

        assertThatNoException().isThrownBy(() -> GraphValidation.check(new SystemGraph(SystemGraph.SCHEMA_VERSION,
                List.of(graph), List.of(link), List.of(carried), List.of(), List.of(), List.of())));
    }

    @Test
    void everyNodeNeedsAnId() {
        // A graph's nodes are sorted by id as it is read, so only a lone node gets this far without one.
        rejected(graph(Arrays.asList((Node) null), List.of(), List.of()), "Every node needs an id");
        rejected(graph(List.of(new Opaque(null, "reflection", HANDLER)), List.of(), List.of()),
                "Every node needs an id");
    }

    @Test
    void anIngressOrEgressNeedsAMethodAndWhereItGoes() {
        rejected(graph(List.of(new Ingress("ingress:? /items", null, "/items", HANDLER, null)), List.of(),
                List.of()), "Ingress ingress:? /items needs a method and a route");
        rejected(graph(List.of(new Egress("egress:a", "RestClient", null, "/stock", null, null, HANDLER, null, null,
                null)), List.of(), List.of()), "Egress egress:a needs a method and a URI template");
        rejected(graph(List.of(new Egress("egress:b", "RestClient", "GET", null, null, null, HANDLER, null, null,
                null)), List.of(), List.of()), "Egress egress:b needs a method and a URI template");
    }

    @Test
    void aFieldNeedsItsIdOwnerAndJsonName() {
        for (Field field : List.of(new Field("field:name", "app.Item", "name", "name", "java.lang.String", List.of(),
                        false, null),
                new Field("field:app.Item.name", null, "name", "name", "java.lang.String", List.of(), false, null),
                new Field("field:app.Item.name", "app.Item", "name", null, "java.lang.String", List.of(), false,
                        null))) {
            rejected(graph(List.of(field), List.of(), List.of()), "Field " + field.id() + " needs an id");
        }
    }

    @Test
    void aLocationNeedsAScopeAndARequirementOfAKnownKind() {
        for (AuthorizationLocation location : List.of(location(null, Requirement.authenticated()),
                location(AuthorizationLocation.Scope.METHOD, null),
                location(AuthorizationLocation.Scope.METHOD, new Requirement(null, null, null, null)),
                location(AuthorizationLocation.Scope.METHOD, Requirement.or(List.of(Requirement.authenticated(),
                        new Requirement(null, null, null, "hasRole('X')")))))) {
            rejected(graph(List.of(location), List.of(), List.of()), "Location " + location.id()
                    + " needs a scope and a requirement of a known kind");
        }
    }

    @Test
    void anEdgeNeedsBothEnds() {
        rejected(graph(List.of(ITEMS), List.of(Edge.local(ITEMS.id(), ITEMS.id(), null, 1, List.of())), List.of()),
                "An edge needs both ends");
        rejected(graph(List.of(ITEMS), List.of(Edge.local(ITEMS.id(), null, ITEMS.id(), 1, List.of())), List.of()),
                "An edge needs both ends");
    }

    @Test
    void aSystemsLinksAndFlowsJoinQualifiedIds() {
        ApplicationGraph graph = graph(List.of(ITEMS), List.of(), List.of());
        for (Edge link : List.of(
                new Edge("egress:a", "stock/ingress:GET /stock", Edge.Kind.NETWORK_INFERRED, null, 0, List.of(), true),
                new Edge("items/egress:a", "/ingress:GET /stock", Edge.Kind.NETWORK_INFERRED, null, 0, List.of(),
                        true),
                new Edge("items/egress:a", null, Edge.Kind.NETWORK_INFERRED, null, 0, List.of(), true))) {
            rejected(new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(graph), List.of(link), List.of(), List.of(),
                    List.of(), List.of()), "A link joins qualified ids");
        }
        for (Flow flow : List.of(
                new Flow("items/egress:a", "field:app.Stock.name", "items/field:app.Item.name", FieldSource.DIRECT,
                        Flow.Kind.NETWORK),
                new Flow("items/egress:a", "stock/field:app.Stock.name", "field:app.Item.name", FieldSource.DIRECT,
                        Flow.Kind.NETWORK))) {
            rejected(new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(graph), List.of(), List.of(flow),
                    List.of(), List.of(), List.of()), "A system flow joins qualified ids");
        }
    }

    private static void rejected(ApplicationGraph graph, String message) {
        assertThatIllegalArgumentException().isThrownBy(() -> GraphValidation.check(graph))
                .withMessageStartingWith(message);
    }

    private static void rejected(SystemGraph system, String message) {
        assertThatIllegalArgumentException().isThrownBy(() -> GraphValidation.check(system))
                .withMessageStartingWith(message);
    }

    private static AuthorizationLocation location(AuthorizationLocation.Scope scope, Requirement requirement) {
        return new AuthorizationLocation("location:METHOD:app.Items#list", "@PreAuthorize", scope,
                AuthorizationLocation.Phase.PRE, requirement, HANDLER, null, null, AuthorizationLocation.Denial.THROW,
                true);
    }

    private static ApplicationGraph graph(List<Node> nodes, List<Edge> edges, List<ProvidedFact> provided) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "items", "r1", 9000, AuthoritySource.UNKNOWN,
                new ArrayList<>(nodes), edges, List.of(), provided, List.of());
    }
}
