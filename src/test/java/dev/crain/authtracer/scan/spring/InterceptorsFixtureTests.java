package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.spring.FiltersFixtureTests.steps;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-17 (decision 0070): Spring MVC's HandlerInterceptors around the handlers of the mappings they match.
 */
class InterceptorsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("interceptors");

    @Test
    void interceptorsRunInOrderBeforeTheHandlerAndInReverseAfterIt() {
        // preHandle in order (timing 0, audit 1, tenant 2); then every postHandle, then every afterCompletion, each
        // in reverse.
        assertThat(steps(graph, "ingress:GET /api/orders")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "egress GET /tenants", "egress POST /timings",
                "egress POST /audit");
    }

    @Test
    void pathPatternsNarrowAnInterceptor() {
        for (String ingress : new String[] {"ingress:GET /api/public/info", "ingress:GET /home"}) {
            assertThat(steps(graph, ingress)).as(ingress).containsExactly(
                    "check Spring Boot default SecurityFilterChain", "egress POST /timings", "egress POST /audit");
        }
    }

    @Test
    void aServletOfItsOwnPassesNoInterceptor() {
        assertThat(steps(graph, "ingress:GET /legacy/**")).containsExactly(
                "check Spring Boot default SecurityFilterChain");
    }

    @Test
    void anInterceptorThatDeniesByHandIsAHandRolledCheck() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .extracting(Finding::message).singleElement().satisfies(message -> assertThat(message)
                        .contains("fixtures.interceptors.AuditInterceptor#preHandle",
                                "HttpServletRequest.isUserInRole()", "sendError(403)"));
    }
}
