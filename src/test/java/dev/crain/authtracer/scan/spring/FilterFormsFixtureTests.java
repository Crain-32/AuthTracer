package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.spring.FiltersFixtureTests.steps;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-17 (decision 0070): the other ways filters are added to a chain and registered, and how each is ordered.
 */
class FilterFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("filterforms");

    @Test
    void aChainsFiltersRunInFilterOrderRegistrationsOrder() {
        // addFilter(subclass of UsernamePasswordAuthenticationFilter) at 2100, its hook for login requests only;
        // addFilterAt(BasicAuthenticationFilter) at 3100, a filter after it at 3101; before the anonymous filter at
        // 3699; after ExceptionTranslationFilter at 4001; a lambda before the AuthorizationFilter (4200); a helper's
        // after it.
        assertThat(steps(graph, "ingress:GET /things")).containsExactly("egress GET /first?", "egress GET /login?",
                "egress GET /token", "egress GET /token-audit",
                "opaque Filter AuthTracer can't resolve (the Filter FilterFactory#create returns)",
                "egress GET /translated", "egress GET /lambda", "check authorizeHttpRequests", "egress GET /helper",
                "egress GET /late");
    }

    @Test
    void aFilterAuthTracerCantResolveIsAnOpaqueStep() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH)
                .extracting(Finding::message).contains("On GET /things: the request passes the Filter"
                        + " FilterFactory#create returns, registered in fixtures.filterforms.FormsChain#chain("
                        + "org.springframework.security.config.annotation.web.builders.HttpSecurity,"
                        + "fixtures.filterforms.FilterFactory); what it does is not in the graph");
    }

    @Test
    void theKotlinDslAddsFiltersToo() {
        assertThat(steps(FixtureScans.scan("kotlinfilters"), "ingress:GET /keyed")).containsExactly(
                "egress GET /keys", "check authorizeHttpRequests");
    }

    @Test
    void aWebFilterAndAFilterRegistrationCoverTheirUrlPatternsAtTheirOrder() {
        assertThat(steps(graph, "ingress:GET /reports/daily")).endsWith("check authorizeHttpRequests",
                "egress GET /helper", "egress GET /reports-access", "egress GET /late");
        assertThat(steps(graph, "ingress:GET /admin/users")).startsWith("egress GET /first?",
                "egress GET /admin-access", "egress GET /login?");
        assertThat(steps(graph, "ingress:GET /things")).doesNotContain("egress GET /reports-access",
                "egress GET /admin-access");
    }
}
