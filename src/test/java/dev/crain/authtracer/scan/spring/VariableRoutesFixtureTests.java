package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A rule narrower than a route with a path variable takes the route's requests it matches (decision 0080's reading,
 * for variables), unless a more specific mapping answers those paths.
 */
class VariableRoutesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("variableroutes");

    @Test
    void aNarrowerRuleTakesPartOfARouteWithAVariable() {
        AuthorizationLocation report = rule(graph, "GET /reports/{type}");
        assertThat(report.id()).startsWith("location:SPLIT:");
        assertThat(report.requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Requirement.Kind.PERMIT_ALL, Requirement.Kind.ANY_AUTHORITY);
    }

    @Test
    void aPathAMoreSpecificMappingAnswersDoesntReachTheRoute() {
        assertThat(rule(graph, "GET /users/{id}").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(graph, "GET /users/me").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }

    @Test
    void aSampleFillsInWildcardsAndVariables() {
        assertThat(HttpSecurityRules.Matcher.sample("/reports/public-*/{id}/**")).isEqualTo("/reports/public-x/x/x");
        assertThat(HttpSecurityRules.Matcher.overlaps("/reports/{type}", "/reports/a/b")).isFalse();
        assertThat(HttpSecurityRules.Matcher.overlaps("[", "/x")).isFalse();
    }
}
