package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0080: functional routes AuthTracer reads only in part are still ways in, with a finding for what it can't
 * read.
 */
class FunctionalUnreadFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("functionalunread");

    @Test
    void everyAlternativeOfAnOrAndOfMethodsIsAWayIn() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /orders",
                "ingress:GET /purchases", "ingress:PUT /orders/{id}", "ingress:PATCH /orders/{id}");
        assertThat(handler("ingress:GET /purchases")).startsWith("list(");
    }

    @Test
    void aPredicateConstantIsRead() {
        assertThat(handler("ingress:GET /catalog")).startsWith("list(");
        assertThat(opaque()).noneMatch(message -> message.contains("GET /catalog"));
    }

    @Test
    void aLambdaThatNarrowsAKnownRouteKeepsItsMethodAndPathWithAFinding() {
        assertThat(handler("ingress:POST /orders")).startsWith("create(");
        assertThat(handler("ingress:GET /reports")).startsWith("list(");
        // Decision 0089 (amended): named by the method it is written in.
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#orders(",
                "(a lambda in fixtures.functionalunread.FunctionalUnreadApp#orders(", "it is shown as POST /orders")
                .doesNotContain("lambda$"));
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#reports(", "a lambda in ",
                "it is shown as GET /reports"));
    }

    @Test
    void predicatesThatSayNothingReadableAboutThePathAnswerEveryRequestAndMayMatchAnyRule() {
        // The custom RequestPredicate, the negated one and a builder route on a lambda alone.
        assertThat(graph.nodes(Ingress.class)).filteredOn(ingress -> ingress.route().equals("/**"))
                .allSatisfy(ingress -> assertThat(ingress.httpMethod()).isEqualTo("*"))
                .extracting(ingress -> ingress.handler().method())
                .containsExactlyInAnyOrder("tenant(org.springframework.web.reactive.function.server.ServerRequest)",
                        "fallback(org.springframework.web.reactive.function.server.ServerRequest)",
                        "purge(org.springframework.web.reactive.function.server.ServerRequest)");
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains(
                "the custom RequestPredicate TenantPredicate", "it is shown as * /**"));
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("(negate())"));
        // Any path may be under /admin/** or /export, whose rules ask for more.
        assertThat(rule(graph, "* /**").mechanism()).contains("narrower rules match part of the route");
    }

    @Test
    void handlerFunctionClassesHandleTheirRoutes() {
        assertThat(handler("ingress:GET /export")).startsWith("handle(");
        assertThat(((Ingress) graph.node("ingress:GET /export").orElseThrow()).handler().className())
                .isEqualTo("fixtures.functionalunread.ExportFunction");
        assertThat(((Ingress) graph.node("ingress:GET /export").orElseThrow()).response())
                .isEqualTo(new Payload("fixtures.functionalunread.Order", false));
        assertThat(rule(graph, "GET /export").requirement().authorities()).containsExactly("ROLE_AUDITOR");
        assertThat(((Ingress) graph.node("ingress:GET /admin/audit").orElseThrow()).handler().className())
                .isEqualTo("fixtures.functionalunread.AuditFunction");
    }

    @Test
    void aHandlerItCantFollowKeepsTheRouteAtTheRouterBean() {
        Ingress hooks = (Ingress) graph.node("ingress:GET /hooks/{name}").orElseThrow();
        assertThat(hooks.handler().method()).startsWith("orders(");
        assertThat(rule(graph, "GET /hooks/{name}").routePattern()).isEqualTo("anyExchange");
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("routes GET /hooks/{name} to a"
                + " handler AuthTracer can't follow (what java.util.Map#get(java.lang.Object) returns)"));
        // Spring would pick one of two by the parameter's name.
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("routes GET /audits to a handler",
                "(one of the application's 2 HandlerFunction beans)"));
    }

    @Test
    void routesItCantReadAtAllAreAFindingOnTheirBean() {
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#orders(", "also has routes",
                "a RouterFunction from the field pluginRoutes"));
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#plugins() builds its routes",
                "the custom RouterFunction PluginRouter"));
        // Another RouterFunction bean, served at /api too.
        assertThat(opaque()).anySatisfy(message -> assertThat(message).contains("#api(",
                "also has routes AuthTracer can't read (a RouterFunction from a bean method parameter)"));
    }

    @Test
    void springMvcHandlerFunctionsNestedOrsAndNonConstantPaths() {
        ApplicationGraph mvc = FixtureScans.scan("functionalmvcunread");
        assertThat(mvc.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:GET /api/items", "ingress:GET /api/stock", "ingress:GET /api/inventory",
                "ingress:DELETE /api/admin/items/{id}", "ingress:DELETE /**", "ingress:* /health",
                "ingress:* /verbs", "ingress:GET /legacy");
        // The only HandlerFunction bean is the one injected by its interface, and its checks are on the path.
        assertThat(path(mvc, "ingress:GET /api/items")).last().asString().endsWith("ItemService#list():@PreAuthorize");
        assertThat(rule(mvc, "DELETE /api/admin/items/{id}").requirement().authorities()).containsExactly("ROLE_ADMIN");
        List<String> findings = mvc.findings().stream().map(Finding::message).toList();
        assertThat(findings).anySatisfy(message -> assertThat(message).contains("a lambda in ",
                "it is shown as DELETE /api/admin/items/{id}"));
        assertThat(findings).anySatisfy(message -> assertThat(message).contains("(a path that isn't a constant)",
                "it is shown as DELETE /**"));
        assertThat(findings).anySatisfy(message -> assertThat(message).contains(
                "(an HTTP method that isn't a constant)", "it is shown as * /verbs"));
        assertThat(findings).anySatisfy(message -> assertThat(message).contains("routes GET /legacy to a handler"));
    }

    @Test
    void theKotlinDslsInvokedPredicatesAndRoutesByPathOrMediaType() {
        ApplicationGraph kotlin = FixtureScans.scan("kotlinroutesunread");
        assertThat(kotlin.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:GET /products", "ingress:GET /catalog", "ingress:* /search", "ingress:* /health",
                "ingress:GET /admin/stats", "ingress:* /**", "ingress:* /**?handler=fixtures.kotlinroutesunread"
                        + ".ShopHandler#beta(org.springframework.web.reactive.function.server.ServerRequest)");
        assertThat(((Ingress) kotlin.node("ingress:* /health").orElseThrow()).handler().method())
                .startsWith("health(");
        assertThat(kotlin.findings()).singleElement().satisfies(finding -> assertThat(finding.message())
                .contains("(not(..))"));
    }

    @Test
    void gatewayServerMvcRoutesAreLeftToTheGatewayReader() {
        assertThat(FixtureScans.scan("gatewaymvcforms").findings()).noneMatch(finding -> finding.message()
                .contains("RouterFunction bean"));
    }

    private String handler(String ingress) {
        return ((Ingress) graph.node(ingress).orElseThrow()).handler().method();
    }

    private List<String> opaque() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .map(Finding::message).toList();
    }
}
