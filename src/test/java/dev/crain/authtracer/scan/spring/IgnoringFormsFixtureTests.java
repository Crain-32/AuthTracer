package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Requests a WebSecurityCustomizer's ignoring() matches skip every chain; one a matcher may match, on a header the
 * caller sends (HTTP-06) or one AuthTracer can't evaluate, may skip them (decision 0051), and is reported; a
 * customizer that only sets the firewall ignores nothing.
 */
class IgnoringFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("ignoringforms");

    @Test
    void eachIgnoredPatternSkipsTheChain() {
        assertThat(rule(graph, "GET /assets/logo").mechanism()).startsWith("WebSecurityCustomizer ignoring()");
        assertThat(rule(graph, "GET /assets/logo").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void aHeaderTheCallerSendsMaySkipTheChain() {
        AuthorizationLocation orders = rule(graph, "GET /orders");
        assertThat(orders.mechanism())
                .isEqualTo("WebSecurityCustomizer ignoring() (may match first and skip the filter chain)");
        assertThat(orders.routePattern()).isEqualTo("when header User-Agent or anyRequest");
        assertThat(orders.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.PERMIT_ALL, Kind.AUTHENTICATED);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .isEqualTo("ignoring() in fixtures.ignoringforms.IgnoringFormsConfig#ignoring() matches when"
                                + " header User-Agent, which depends on what the caller sends (the header"
                                + " User-Agent): a caller who sends it skips every SecurityFilterChain"));
    }

    @Test
    void anIgnoredRequestMatcherAuthTracerCantEvaluateIsReported() {
        ApplicationGraph unread = FixtureScans.scan("ignoringunread");
        assertThat(unread.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("ignoring() in fixtures.ignoringunread.IgnoringUnreadConfig#localProbes()")
                        .contains("uses a RequestMatcher AuthTracer can't evaluate"));
        assertThat(rule(unread, "GET /health/details").requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.PERMIT_ALL, Kind.ANY_AUTHORITY);
    }
}
