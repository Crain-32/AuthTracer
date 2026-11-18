package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.spring.FiltersFixtureTests.steps;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-17 (decision 0070) on WebFlux: WebFilters in the chain and WebFilter beans.
 */
class WebFiltersFixtureTests {

    @Test
    void aChainsWebFiltersRunAroundAuthorizationAndWebFilterBeansAroundTheChain() {
        assertThat(steps(FixtureScans.scan("webfilters"), "ingress:GET /items")).containsExactly(
                "egress POST /spans", "egress GET /tenants/current", "check authorizeExchange",
                "egress POST /quotas/use", "egress POST /wrapped", "egress POST /hits");
    }

    @Test
    void aWebFilterAtLastRunsAfterAuthorizationAndAComponentRunsItsBaseClassesCode() {
        assertThat(steps(FixtureScans.scan("webfilterforms"), "ingress:GET /things")).containsExactly(
                "check authorizeExchange", "egress POST /last", "egress POST /stamps");
    }
}
