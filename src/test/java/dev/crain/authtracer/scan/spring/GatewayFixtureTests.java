package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0043: Spring Cloud Gateway routes.
 */
class GatewayFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("gateway");

    @Test
    void routesAreIngressThatForward() {
        assertThat(graph.nodes()).filteredOn(Ingress.class::isInstance).map(node -> ((Ingress) node).id())
                .contains("ingress:GET /api/employees/**", "ingress:* /admin/**", "ingress:GET /api/teams/**",
                        "ingress:POST /api/teams/**");
        List<Egress> egress = graph.nodes().stream().filter(Egress.class::isInstance).map(Egress.class::cast)
                .toList();
        assertThat(egress).extracting(Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl, Egress::credentials)
                .contains(tuple("GET", "/employees/**", "http://localhost:8082", Credentials.RELAY),
                        tuple("*", "/internal/**", "http://employee-service", Credentials.NONE),
                        tuple("GET", "/teams/**", "http://localhost:8083", Credentials.RELAY),
                        tuple("POST", "/teams/**", "http://localhost:8083", Credentials.RELAY));
    }

    @Test
    void theGatewaysOwnRulesComeFirst() {
        List<String> steps = path(graph, "ingress:* /admin/**");
        assertThat(steps).hasSize(2);
        AuthorizationLocation rule = (AuthorizationLocation) graph.node(steps.getFirst()).orElseThrow();
        assertThat(rule.requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(steps.getLast()).startsWith("egress:");
    }

    @Test
    void aNarrowerRuleTakesPartOfARoutesRequests() {
        // /api/teams/public/** is open: the route is as open as that part of it.
        AuthorizationLocation rule = (AuthorizationLocation) graph.node(path(graph, "ingress:GET /api/teams/**")
                .getFirst()).orElseThrow();
        assertThat(rule.id()).startsWith("location:SPLIT:");
        assertThat(rule.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Requirement.Kind.PERMIT_ALL, Requirement.Kind.AUTHENTICATED);
        assertThat(((AuthorizationLocation) graph.node(path(graph, "ingress:GET /api/employees/**").getFirst())
                .orElseThrow()).requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void routeArgumentsSpelledOutAndEveryPathAndHeaderFilter() {
        ApplicationGraph forms = FixtureScans.scan("gatewayforms");
        assertThat(forms.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::credentials)
                .containsExactlyInAnyOrder(
                        // A RewritePath's regexp and replacement as arguments; removing a cookie keeps the token.
                        tuple("/invoices/**", "http://localhost:8086", Credentials.RELAY),
                        // Rewritten to nothing: the root.
                        tuple("/", "http://localhost:8087", Credentials.RELAY),
                        tuple("/**", "http://localhost:8087", Credentials.RELAY),
                        // A fixed Authorization header replaces the caller's.
                        tuple("/v2/feed", "https://partner.example.com", Credentials.STATIC),
                        tuple("/api/**", "http://localhost:8088", Credentials.RELAY),
                        // A RouteLocator route with a URI put together from a @Value the lambda captures.
                        tuple("/teams/**", "http://teams.internal:8083", Credentials.RELAY));
        assertThat(forms.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:* /billing/**",
                "ingress:* /red", "ingress:* /red/**", "ingress:* /teams/**");
    }

    @Test
    void defaultFiltersApplyToTheRoutesOfTheProperties() {
        ApplicationGraph defaults = FixtureScans.scan("gatewaydefaults");
        assertThat(defaults.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::credentials)
                .containsExactlyInAnyOrder(
                        // StripPrefix=1 and no Authorization header.
                        tuple("/orders/**", "http://orders:8081", Credentials.NONE),
                        // The route's TokenRelay runs after the default that removes the header.
                        tuple("/stock/**", "http://stock:8082", Credentials.RELAY),
                        // Built by a RouteLocator bean: no default filters.
                        tuple("/api/built/**", "http://built:8083", Credentials.RELAY));
    }

    @Test
    void serverMvcRoutesKeyedById() {
        ApplicationGraph map = FixtureScans.scan("gatewaymvcmap");
        assertThat(map.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /api/payments/**",
                "ingress:POST /api/payments/**", "ingress:* /api/refunds/**");
        assertThat(map.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::credentials)
                .contains(tuple("/payments/**", Credentials.RELAY), tuple("/api/refunds/**", Credentials.STATIC));
        assertThat(((AuthorizationLocation) map.node(path(map, "ingress:GET /api/payments/**").getFirst())
                .orElseThrow()).requirement().authorities()).containsExactly("ROLE_BILLING");
    }

    @Test
    void anAddedAuthorizationHeaderLeavesTheCallersInPlace() {
        assertThat(GatewayRoutes.credentials(List.of("AddRequestHeader=Authorization, Basic x")))
                .isEqualTo(Credentials.RELAY);
        assertThat(GatewayRoutes.credentials(List.of("RemoveRequestHeader=Authorization",
                "AddRequestHeader=Authorization, Basic x"))).isEqualTo(Credentials.STATIC);
    }

    @Test
    void serverMvcRoutesInOneBean() {
        ApplicationGraph forms = FixtureScans.scan("gatewaymvcforms");
        assertThat((Egress) forms.node(path(forms, "ingress:GET /products/**").getLast()).orElseThrow())
                .extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactly("/api/products/**", "http://localhost:8091");
        // No id, a request predicate, and a URI from a property.
        assertThat((Egress) forms.node(path(forms, "ingress:* /legacy/**").getLast()).orElseThrow())
                .extracting(Egress::uriTemplate, Egress::baseUrl).containsExactly("/v1/legacy",
                        "http://localhost:8092");
    }

    @Test
    void withoutTheGatewayItsRoutesAreNone() {
        assertThat(FixtureScans.scanWithout("gateway", "spring-cloud-gateway-server-webflux",
                "spring-cloud-gateway-server-webmvc").nodes(Egress.class)).isEmpty();
        // Server MVC on its own.
        assertThat(FixtureScans.scanWithout("gatewaymvc", "spring-cloud-gateway-server-webflux").nodes(Ingress.class))
                .extracting(Ingress::id).contains("ingress:* /api/orders/**", "ingress:GET /api/invoices/**");
    }

    @Test
    void serverMvcRoutes() {
        ApplicationGraph mvc = FixtureScans.scan("gatewaymvc");
        List<String> steps = path(mvc, "ingress:* /api/orders/**");
        assertThat(((AuthorizationLocation) mvc.node(steps.getFirst()).orElseThrow()).requirement().authorities())
                .containsExactly("ROLE_SALES");
        assertThat((Egress) mvc.node(steps.getLast()).orElseThrow()).extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactly("/orders/**", "http://localhost:8084");
        // A RouterFunction bean's route.
        assertThat((Egress) mvc.node(path(mvc, "ingress:GET /api/invoices/**").getLast()).orElseThrow())
                .extracting(Egress::uriTemplate, Egress::baseUrl, Egress::credentials)
                .containsExactly("/invoices/**", "http://localhost:8085", Credentials.RELAY);
        // filter(lb("users-service")): the load balancer's pick of that service.
        assertThat((Egress) mvc.node(path(mvc, "ingress:GET /api/users/**").getLast()).orElseThrow())
                .extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactly("/api/users/**", "http://users-service");
    }
}
