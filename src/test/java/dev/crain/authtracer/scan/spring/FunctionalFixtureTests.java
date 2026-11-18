package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class FunctionalFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("functional");

    @Test
    void routesBecomeIngresses() {
        assertThat(graph.nodes(Ingress.class)).extracting(ingress -> ingress.httpMethod() + " " + ingress.route())
                .containsExactlyInAnyOrder("GET /books/{id}", "POST /books", "DELETE /admin/books/{id}", "GET /shelves",
                        "GET /legacy/books", "POST /legacy/books");
    }

    @Test
    void theHandlerIsWhereTheRequestPathStarts() {
        List<String> path = path(graph, "ingress:GET /books/{id}");
        assertThat(path).containsExactly(
                "location:HTTP_REQUEST:fixtures.functional.FunctionalApp#app(org.springframework.security.config.web"
                        + ".server.ServerHttpSecurity):1:anyExchange",
                "location:METHOD:fixtures.functional.Catalog#find(long):@PreAuthorize");
        AuthorizationLocation admin = (AuthorizationLocation) graph.node(path(graph, "ingress:DELETE /admin/books/{id}")
                .getFirst()).orElseThrow();
        assertThat(admin.requirement().authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void responseTypesAndLineage() {
        Ingress get = (Ingress) graph.node("ingress:GET /books/{id}").orElseThrow();
        assertThat(get.response()).isEqualTo(new Payload("fixtures.functional.BookView", false));
        Ingress shelves = (Ingress) graph.node("ingress:GET /shelves").orElseThrow();
        assertThat(shelves.response()).isEqualTo(new Payload("fixtures.functional.BookView", true));
        assertThat(graph.flows("ingress:GET /books/{id}")).anySatisfy(flow -> {
            assertThat(flow.from()).isEqualTo("field:fixtures.functional.Book.title");
            assertThat(flow.to()).isEqualTo("field:fixtures.functional.BookView.title");
        });
    }

    @Test
    void aRecordComponentNamedLikeAnIsGetterIsWritten() {
        // Jackson writes a record's components by name: isbn() is BookView's isbn, not an isBn() of a String (found
        // by conformanceTest reading the response).
        assertThat(Exposures.of(graph).stream().filter(exposure -> exposure.endpoint().equals("GET /books/{id}"))
                .map(Exposures.Exposure::field).filter(field -> !field.isEmpty()))
                .containsExactlyInAnyOrder("title", "isbn");
        assertThat(graph.flows("ingress:GET /books/{id}")).anySatisfy(flow -> {
            assertThat(flow.from()).isEqualTo("field:fixtures.functional.Book.isbn");
            assertThat(flow.to()).isEqualTo("field:fixtures.functional.BookView.isbn");
        });
    }

    @Test
    void springMvcFunctionalEndpoints() {
        ApplicationGraph mvc = FixtureScans.scan("functionalmvc");
        AuthorizationLocation status = (AuthorizationLocation) mvc.node(path(mvc, "ingress:GET /api/status")
                .getFirst()).orElseThrow();
        assertThat(status.requirement().authorities()).containsExactly("ROLE_API");
    }

    @Test
    void staticNestAndRoutesFromHelperMethods() {
        ApplicationGraph nested = FixtureScans.scan("functionalnest");
        assertThat(nested.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:GET /api/items", "ingress:POST /api/items", "ingress:DELETE /api/admin/items/{id}",
                "ingress:GET /status");
        assertThat(FixtureScans.rule(nested, "DELETE /api/admin/items/{id}").requirement().authorities())
                .containsExactly("ROLE_ADMIN");
        assertThat(((Ingress) nested.node("ingress:GET /api/items").orElseThrow()).response().type())
                .isEqualTo("fixtures.functionalnest.Item");
    }

    @Test
    void builtRoutesTakeThePrefixOfWhereTheyGo() {
        ApplicationGraph built = FixtureScans.scan("functionalbuilt");
        assertThat(built.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:GET /v1/items", "ingress:GET /v2/items", "ingress:DELETE /admin/items/{id}");
    }

    @Test
    void predicatesNestingByMediaTypeAndRoutesOfEveryPathUnderTheirPrefix() {
        ApplicationGraph predicates = FixtureScans.scan("functionalpredicates");
        // A route without a path of its own (method(..), or GET(handler)) answers every path under its prefix; a
        // nest(..) by media type adds no prefix; resources(..) routes to no handler of the application's.
        assertThat(predicates.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:GET /orders", "ingress:PUT /orders/{id}", "ingress:DELETE /admin/orders/**",
                "ingress:GET /orders/export", "ingress:GET /person/{id}", "ingress:GET /person/**",
                "ingress:POST /person/**", "ingress:POST /people/import", "ingress:GET /people/count",
                "ingress:GET /people/search", "ingress:GET /invoices", "ingress:POST /invoices",
                "ingress:GET /reports/v2");
        assertThat(FixtureScans.rule(predicates, "DELETE /admin/orders/**").requirement().authorities())
                .containsExactly("ROLE_ADMIN");
        assertThat(((Ingress) predicates.node("ingress:GET /orders").orElseThrow()).response())
                .isEqualTo(new Payload("fixtures.functionalpredicates.Order", true));
        assertThat(((Ingress) predicates.node("ingress:GET /invoices").orElseThrow()).response())
                .isEqualTo(new Payload("fixtures.functionalpredicates.Invoice", false));
        // The helper's path, captured by the nested builder's lambda.
        assertThat(((Ingress) predicates.node("ingress:GET /reports/v2").orElseThrow()).handler().method())
                .startsWith("latest(");
        // A body given as a ParameterizedTypeReference names no class.
        assertThat(((Ingress) predicates.node("ingress:GET /orders/export").orElseThrow()).response()).isNull();
    }
}
