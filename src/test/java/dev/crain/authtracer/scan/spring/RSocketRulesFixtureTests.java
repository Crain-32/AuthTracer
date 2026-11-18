package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * RX-13: rules in a lambda that captures what it uses, and the spec's rules and managers the {@code rsocket} fixture
 * doesn't use.
 */
class RSocketRulesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("rsocketrules");

    @Test
    void aManagerTheLambdaCapturesDecidesItsRoute() {
        List<AuthorizationLocation> audit = checks("RSOCKET audit");
        assertThat(audit).extracting(AuthorizationLocation::routePattern).containsExactly("setup()", "route(audit)");
        assertThat(audit.getFirst().requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(audit.getLast().requirement().authorities()).containsExactly("AUDIT");
    }

    @Test
    void eachManagerAndRuleOfTheSpec() {
        assertThat(rule("RSOCKET members").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule("RSOCKET legacy.import").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        Requirement vip = rule("RSOCKET vip").requirement();
        assertThat(vip.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(vip.decidedBy().method()).startsWith("lambda$rsocketInterceptor$");
    }

    @Test
    void aLambdaThatAlwaysGrantsIsPermitAllInDisguise() {
        // (authentication, context) -> Mono.just(new AuthorizationDecision(true)) (decision 0065).
        Requirement open = rule("RSOCKET open").requirement();
        assertThat(open.kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(open.decidedBy().method()).startsWith("lambda$rsocketInterceptor$");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_GRANTED)
                .extracting(Finding::message).anyMatch(message -> message.startsWith(
                        "A lambda in fixtures.rsocketrules.RSocketRulesConfig#rsocketInterceptor("));
        // At the lambda's line in the method it is written in.
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_GRANTED)
                .extracting(Finding::location).anySatisfy(location -> {
                    assertThat(location.method()).startsWith("rsocketInterceptor(");
                    assertThat(location.line()).isNotNull();
                });
    }

    @Test
    void aRouteBuiltAtRuntimeMayMatchAnything() {
        AuthorizationLocation daily = rule("RSOCKET reports.daily");
        assertThat(daily.routePattern()).isEqualTo("route(?) or anyRequest()");
        assertThat(daily.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
    }

    private AuthorizationLocation rule(String ingress) {
        return checks(ingress).getLast();
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().startsWith(RSocketSecurityRules.MECHANISM)).toList();
    }
}
