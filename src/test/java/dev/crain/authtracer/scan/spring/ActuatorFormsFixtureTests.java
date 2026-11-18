package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0041: EndpointRequest matchers narrowed to an HTTP method, or without the links page.
 */
class ActuatorFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("actuatorforms");

    @Test
    void anEndpointMatcherWithAnHttpMethodTakesOnlyThatMethod() {
        assertThat(rule(graph, "POST /actuator/loggers/{name}").requirement().authorities())
                .containsExactly("ROLE_OPS");
        assertThat(rule(graph, "POST /actuator/loggers/{name}").routePattern())
                .isEqualTo("POST /actuator/loggers,/actuator/loggers/**");
        assertThat(rule(graph, "GET /actuator/loggers/{name}").requirement().authorities())
                .containsExactly("ROLE_MONITOR");
    }

    @Test
    void excludingLinksLeavesTheLinksPageOut() {
        assertThat(rule(graph, "GET /actuator/health").requirement().authorities()).containsExactly("ROLE_MONITOR");
        assertThat(rule(graph, "GET /actuator/health").routePattern()).contains("/actuator/health/**")
                .doesNotEndWith(",/actuator");
    }
}
