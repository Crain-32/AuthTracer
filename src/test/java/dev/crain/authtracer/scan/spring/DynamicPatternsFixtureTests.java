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
 * Decision 0051: a RequestMatcher AuthTracer can't evaluate, from any factory, may match a request first.
 */
class DynamicPatternsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("dynamicpatterns");

    @Test
    void rulesBeforeTheFirstUnknownMatcherAreSure() {
        assertThat(rule(graph, "GET /health").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void aRuleWithAKnownAndAnUnknownMatcherTakesWhatTheKnownOneMatches() {
        AuthorizationLocation export = rule(graph, "GET /exports/daily");
        assertThat(export.requirement().authorities()).containsExactly("ROLE_EXPORTER");
        assertThat(export.routePattern()).isEqualTo("/exports/**, requestMatchers(RequestMatcher...)");
    }

    @Test
    void everyUnknownMatcherMayMatchFirstAndIsReported() {
        AuthorizationLocation home = rule(graph, "GET /home");
        assertThat(home.id()).startsWith("location:SPLIT:");
        assertThat(home.requirement().operands()).flatExtracting(Requirement::authorities).containsExactly(
                "ROLE_EXPORTER", "ROLE_PARTNER", "ROLE_REPORTER", "ROLE_FEEDS", "ROLE_LEGACY", "SCOPE_api.read",
                "SCOPE_api.write");
        assertThat(home.requirement().operands()).extracting(Requirement::kind)
                .contains(Kind.REMEMBER_ME, Kind.ALL_AUTHORITIES, Kind.AUTHENTICATED);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("The rule PathPatternRequestMatcher (requires"
                        + " hasRole(PARTNER))"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule PathPatternRequestMatcher (requires"
                        + " hasRole(REPORTER))"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule RegexRequestMatcher (requires"
                        + " hasRole(FEEDS))"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule new RegexRequestMatcher(..) (requires"
                        + " hasRole(LEGACY))"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule PathPatternRequestMatcher (requires"
                        + " rememberMe)"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule PathPatternRequestMatcher (requires"
                        + " hasAllAuthorities(SCOPE_api.read,SCOPE_api.write))"));
    }
}
