package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.spring.FiltersFixtureTests.steps;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-17 (decision 0070): which filters Spring Boot registers, for which requests, and where.
 */
class FilterRegistrationsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("filterregistrations");

    @Test
    void servletNamesMayCoverAnyRequestAndNothingCoversEvery() {
        assertThat(steps(graph, "ingress:GET /status")).contains("egress GET /named-web?", "egress GET /bare-web",
                "egress GET /named-bean?", "egress GET /servlet-names?", "egress GET /lambda-bean");
    }

    @Test
    void servletNamesBesideUrlPatternsAndAnEnabledFlagAuthTracerCantReadMayRunTheFilterForAnyRequest() {
        assertThat(steps(graph, "ingress:GET /status")).contains("egress GET /both?", "egress GET /toggled?",
                "egress GET /ordered");
        assertThat(steps(graph, "ingress:GET /reports/{id}")).contains("egress GET /both?");
    }

    @Test
    void disabledAndLibraryFiltersAndABeanItsRegistrationTakesOverAreNotRunAgain() {
        assertThat(steps(graph, "ingress:GET /status")).doesNotContain("egress GET /disabled-bean",
                "egress GET /trace", "egress GET /audit");
        assertThat(steps(graph, "ingress:GET /reports/{id}")).containsOnlyOnce("egress GET /audit");
    }

    @Test
    void anOrderAuthTracerCantReadPutsTheFilterAheadOfSpringSecurity() {
        assertThat(steps(graph, "ingress:GET /status")).startsWith("egress GET /root",
                "check Spring Boot default SecurityFilterChain");
    }

    @Test
    void urlPatternsLongerOrShorterThanTheRouteDontCoverItAndADoubleWildcardMay() {
        assertThat(steps(graph, "ingress:GET /reports/{id}")).doesNotContain("egress GET /summary",
                "egress GET /summary?");
        assertThat(steps(graph, "ingress:GET /files/**")).contains("egress GET /archive?");
        assertThat(steps(graph, "ingress:GET /status")).doesNotContain("egress GET /archive?");
    }

    @Test
    void aBeanMethodThatPicksItsFilterIsOneAuthTracerCantResolveNamingWhatItMayBe() {
        assertThat(steps(graph, "ingress:GET /status")).contains(
                "opaque Filter AuthTracer can't resolve (one of StrictFilter, RelaxedFilter, picked in code)",
                "opaque Filter AuthTracer can't resolve (one of StrictFilter, a library class, picked in code)")
                .doesNotContain("egress GET /strict", "egress GET /relaxed");
    }
}
