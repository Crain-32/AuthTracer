package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * RX-01 and RX-03: WebFlux chains matched by a path and method, or by every exchange, and their rules.
 */
class WebFluxFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("webfluxforms");

    @Test
    void aSecurityMatcherWithAMethodTakesOnlyThatMethod() {
        Requirement stats = rule(graph, "GET /internal/stats").requirement();
        assertThat(stats.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(stats.expression()).isEqualTo("hasIpAddress(10.0.0.0/8)");
        assertThat(rule(graph, "DELETE /internal/stats").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void theEveryExchangeChainsRules() {
        assertThat(rule(graph, "OPTIONS /orders").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "OPTIONS /orders").routePattern()).isEqualTo("OPTIONS /**");
        assertThat(rule(graph, "GET /orders").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(graph, "GET /orders").routePattern()).isEqualTo("anyExchange");
        assertThat(rule(graph, "GET /css/app").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }
}
