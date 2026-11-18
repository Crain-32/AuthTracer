package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Handlers whose result comes later: Spring MVC's asynchronous types, and Kotlin's Flow and suspend functions.
 */
class AsyncResultsFixtureTests {

    @Test
    void anAsynchronousResultIsWhatItCompletesWith() {
        ApplicationGraph graph = FixtureScans.scan("asyncresults");
        for (String route : List.of("/callable", "/deferred", "/task")) {
            assertThat(response(graph, route)).as(route).isEqualTo(new Payload("fixtures.asyncresults.Report", false));
        }
        assertThat(response(graph, "/stage")).isEqualTo(new Payload("fixtures.asyncresults.Report", true));
    }

    @Test
    void aKotlinFlowIsManyOfItsElements() {
        ApplicationGraph graph = FixtureScans.scan("kotlinflows");
        assertThat(response(graph, "/reports")).isEqualTo(new Payload("fixtures.kotlinflows.Report", true));
        assertThat(response(graph, "/report")).isEqualTo(new Payload("fixtures.kotlinflows.Report", false));
    }

    private static Payload response(ApplicationGraph graph, String route) {
        return ((Ingress) graph.node("ingress:GET " + route).orElseThrow()).response();
    }
}
