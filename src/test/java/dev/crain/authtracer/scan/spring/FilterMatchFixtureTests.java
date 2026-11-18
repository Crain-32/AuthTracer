package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.spring.FiltersFixtureTests.steps;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-17 (decision 0070): a filter AuthTracer can only say may run for a request runs on some of its requests
 * (conditional).
 */
class FilterMatchFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("filtermatch");

    @Test
    void aChainThatMayTakeTheRequestFirstMayRunItsFiltersInsteadOfTheNextChains() {
        // The audit and token-check filters are beans too, so Boot also registers them for every request.
        assertThat(steps(graph, "ingress:GET /home")).containsExactly("egress GET /early", "egress GET /partner?",
                "egress GET /audit", "egress GET /token-check",
                "check authorizeHttpRequests (a securityMatcher may match first)", "egress GET /gate?",
                "egress GET /named?", "egress GET /dynamic?", "egress GET /exact");
    }

    @Test
    void aUrlPatternATemplateVariableMayMatchCoversTheRequestConditionally() {
        assertThat(steps(graph, "ingress:GET /accounts/{tenant}/orders")).endsWith("egress GET /gate?",
                "egress GET /tenant?", "egress GET /named?", "egress GET /dynamic?");
        assertThat(steps(graph, "ingress:GET /data/{file}")).endsWith("egress GET /gate?", "egress GET /json?",
                "egress GET /named?", "egress GET /dynamic?");
        assertThat(steps(graph, "ingress:GET /data/report.json")).endsWith("egress GET /gate?", "egress GET /json",
                "egress GET /named?", "egress GET /dynamic?");
    }

    @Test
    void aRequestIgnoringMayTakeOutOfTheChainMaySkipItsFilters() {
        assertThat(steps(FixtureScans.scan("filterignoring"), "ingress:GET /status")).contains("egress GET /screen?",
                "opaque Filter AuthTracer can't resolve (the Filter FilterFactory#create returns)?")
                .doesNotContain("egress GET /screen");
    }
}
