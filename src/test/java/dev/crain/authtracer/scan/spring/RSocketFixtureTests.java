package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0045 (RX-13): RSocket routes and {@code RSocketSecurity.authorizePayload} rules.
 */
class RSocketFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("rsocket");

    @Test
    void messageMappingsAreRoutesJoinedWithDots() {
        assertThat(graph.nodes(Ingress.class)).filteredOn(RSocketMappings::isRSocket).extracting(Ingress::id)
                .containsExactlyInAnyOrder(
                "ingress:RSOCKET profile.{name}", "ingress:RSOCKET status", "ingress:RSOCKET admin.reset",
                "ingress:RSOCKET audit", "ingress:RSOCKET metrics", "ingress:RSOCKET orders.list",
                "ingress:RSOCKET orders.cancel");
        assertThat(ingress("ingress:RSOCKET profile.{name}").response().type()).isEqualTo("fixtures.rsocket.Profile");
        assertThat(ingress("ingress:RSOCKET orders.list").response().many()).isTrue();
        // The RSocket server's own port is one the linker matches calls to.
        assertThat(graph.additionalPorts()).contains(7000);
    }

    @Test
    void eachRequestPassesTheSetupRuleThenTheFirstMatchingRouteRule() {
        List<AuthorizationLocation> status = checks("ingress:RSOCKET status");
        assertThat(status).extracting(AuthorizationLocation::routePattern).containsExactly("setup()", "route(status)");
        assertThat(status.getFirst().requirement().authorities()).containsExactly("ROLE_SETUP");
        assertThat(status.getLast().requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule("ingress:RSOCKET profile.{name}").routePattern()).isEqualTo("route(profile.{name})");
        assertThat(rule("ingress:RSOCKET audit").requirement().authorities()).containsExactly("AUDIT");
        assertThat(rule("ingress:RSOCKET orders.list").routePattern()).isEqualTo("route(orders.**)");
    }

    @Test
    void rsocketRolesGetNoHierarchy() {
        // AuthorityReactiveAuthorizationManager: ROLE_ADMIN > ROLE_USER doesn't widen it.
        assertThat(rule("ingress:RSOCKET admin.reset").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_OPS");
    }

    @Test
    void aRouteOnlyACustomMatcherMayMatchIsItsOrDenied() {
        // matcher(PayloadExchangeMatcher) can't be evaluated, so it may match (decision 0051); no other rule does.
        AuthorizationLocation metrics = rule("ingress:RSOCKET metrics");
        assertThat(metrics.requirement().kind()).isEqualTo(Requirement.Kind.OR);
        assertThat(metrics.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Requirement.Kind.ANY_AUTHORITY, Requirement.Kind.DENY_ALL);
        assertThat(metrics.mechanism()).contains("a matcher may match first");
        assertThat(metrics.routePattern()).isEqualTo("matcher(PayloadExchangeMatcher) or default");
    }

    @Test
    void methodSecurityFollowsTheRouteRule() {
        assertThat(checks("ingress:RSOCKET orders.cancel")).extracting(AuthorizationLocation::mechanism)
                .containsExactly(RSocketSecurityRules.MECHANISM, RSocketSecurityRules.MECHANISM, "@PreAuthorize");
    }

    @Test
    void withoutAnInterceptorBeanTheDefaultRulesApplyAfterTheWebSocketHandshake() {
        ApplicationGraph defaults = FixtureScans.scan("rsocketdefault");
        List<AuthorizationLocation> hello = checks(defaults, "ingress:RSOCKET hello");
        assertThat(hello).extracting(AuthorizationLocation::mechanism).containsExactly("authorizeExchange",
                RSocketSecurityRules.MECHANISM, RSocketSecurityRules.MECHANISM);
        assertThat(hello.getFirst().routePattern()).isEqualTo("/rsocket");
        assertThat(hello).extracting(AuthorizationLocation::routePattern).endsWith("setup()", "anyRequest()");
        assertThat(hello.getLast().requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void anInterceptorWithoutAuthorizePayloadAuthorizesNothing() {
        ApplicationGraph open = FixtureScans.scan("rsocketopen");
        assertThat(open.node("ingress:RSOCKET echo")).isPresent();
        assertThat(checks(open, "ingress:RSOCKET echo")).isEmpty();
    }

    @Test
    void authorizePayloadWithNoRulesDeniesEveryExchange() {
        ApplicationGraph closed = FixtureScans.scan("rsocketclosed");
        assertThat(checks(closed, "ingress:RSOCKET echo")).isNotEmpty().allSatisfy(check -> {
            assertThat(check.requirement()).isEqualTo(Requirement.denyAll());
            assertThat(check.mechanism()).contains("no rule matched");
        });
        // Rules from a customizer passed in can't be read: an opaque check, and a finding that says so.
        ApplicationGraph opaque = FixtureScans.scan("rsocketopaque");
        assertThat(checks(opaque, "ingress:RSOCKET echo")).isNotEmpty().allSatisfy(check ->
                assertThat(check.requirement().expression()).isEqualTo("authorizePayload(customizer)"));
        assertThat(opaque.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .anySatisfy(finding -> assertThat(finding.message()).contains("can't read"));
    }

    @Test
    void aPortTheEnvironmentSetsStartsAServerOfItsOwn() {
        ApplicationGraph envPort = FixtureScans.scan("rsocketenvport");
        // A mapping with no route of its own adds none to its class's, or its method's.
        assertThat(envPort.nodes(Ingress.class)).filteredOn(RSocketMappings::isRSocket).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:RSOCKET quotes", "ingress:RSOCKET quotes.latest",
                        "ingress:RSOCKET ping");
        // Over WebSocket on its own port, beside the WebFlux server: the HTTP rule denying /rsocket isn't on the way.
        assertThat(checks(envPort, "ingress:RSOCKET quotes")).isNotEmpty()
                .noneMatch(check -> check.mechanism().equals("authorizeExchange"));
        // The port is only known when it runs.
        assertThat(envPort.additionalPorts()).isEmpty();
    }

    @Test
    void aMappingPathOverTcpStartsNoServer() {
        assertThat(FixtureScans.scan("rsockettcppath").nodes(Ingress.class)).noneMatch(RSocketMappings::isRSocket);
    }

    @Test
    void requesterCallsAreEgressLinkedToTheRoutes() {
        ApplicationGraph client = FixtureScans.scan("rsocketclient");
        assertThat(client.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::credentials)
                .containsExactlyInAnyOrder(tuple("profile.{name}", "tcp://localhost:7000", Credentials.STATIC),
                        tuple("orders.list", "tcp://localhost:7000", Credentials.STATIC),
                        tuple("audit", "tcp://localhost:7000", Credentials.STATIC));
        assertThat(client.nodes(Egress.class)).filteredOn(egress -> egress.uriTemplate().equals("orders.list"))
                .singleElement().satisfies(egress -> {
                    assertThat(egress.response().type()).isEqualTo("fixtures.rsocketclient.Order");
                    assertThat(egress.response().many()).isTrue();
                });
        SystemGraph system = new Linker().link(List.of(client, graph), ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).containsExactlyInAnyOrder(
                "rsocket/ingress:RSOCKET profile.{name}", "rsocket/ingress:RSOCKET orders.list",
                "rsocket/ingress:RSOCKET audit");
        // The requester's fixed credentials are the client's, so the route rules check the client.
        assertThat(system.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("RSOCKET audit", "fixed credentials (UsernamePasswordMetadata)"));
    }

    @Test
    void requestersBuiltAndUsedInOtherWays() {
        ApplicationGraph client = FixtureScans.scan("rsocketclientforms");
        // Over a WebSocket with a bearer token AuthTracer can't follow; over TCP with the host from a property, and
        // with a port the environment sets; a route from a parameter is a route AuthTracer can't read (decision 0082).
        assertThat(client.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::baseUrl, Egress::credentials,
                Egress::credentialsVia).containsExactlyInAnyOrder(
                        tuple("quote.{symbol}", "ws://quotes:7001", Credentials.UNKNOWN, "BearerTokenMetadata"),
                        tuple("quotes.ticks", "ws://quotes:7001", Credentials.UNKNOWN, "BearerTokenMetadata"),
                        tuple("?", "ws://quotes:7001", Credentials.UNKNOWN, "BearerTokenMetadata"),
                        tuple("feed.first", "tcp://feed.internal:7002", Credentials.NONE, null),
                        tuple("feed.second", "tcp://feed.internal:7002", Credentials.NONE, null),
                        tuple("alerts.raise", null, Credentials.NONE, null));
        // A request's response is read before the next request's route, and a send() has none.
        assertThat(client.nodes(Egress.class)).extracting(Egress::uriTemplate,
                egress -> egress.response() == null ? null : egress.response().type() + (egress.response().many()
                        ? "[]" : "")).containsExactlyInAnyOrder(
                                tuple("quote.{symbol}", "fixtures.rsocketclientforms.Quote"),
                                tuple("quotes.ticks", "fixtures.rsocketclientforms.Quote[]"),
                                tuple("?", "fixtures.rsocketclientforms.Quote"),
                                tuple("feed.first", null), tuple("feed.second", "java.lang.String"),
                                tuple("alerts.raise", null));
    }

    private Ingress ingress(String id) {
        return (Ingress) graph.node(id).orElseThrow();
    }

    private AuthorizationLocation rule(String ingress) {
        return checks(ingress).get(1);
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return checks(graph, ingress);
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
