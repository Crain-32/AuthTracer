package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.spring.FiltersFixtureTests.steps;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-17 (decision 0070): interceptors whose patterns AuthTracer reads only in part may run, and one it can't resolve
 * is an Opaque step.
 */
class InterceptorFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("interceptorforms");

    @Test
    void patternsAuthTracerCantReadMayTakeInOrLeaveOutAnyRequest() {
        assertThat(steps(graph, "ingress:GET /home")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "egress GET /guard?", "egress POST /metrics?");
    }

    @Test
    void anInterceptorAFactoryMakesIsAnOpaqueStepOnTheRequestsItCovers() {
        assertThat(steps(graph, "ingress:GET /admin/users")).containsExactly(
                "check Spring Boot default SecurityFilterChain", "egress GET /guard?",
                "opaque Interceptor AuthTracer can't resolve (the HandlerInterceptor InterceptorFactory#create"
                        + " returns)",
                "egress POST /metrics?");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH)
                .extracting(Finding::message).singleElement().asString().startsWith("On GET /admin/users: the"
                        + " request passes the HandlerInterceptor InterceptorFactory#create returns");
    }
}
