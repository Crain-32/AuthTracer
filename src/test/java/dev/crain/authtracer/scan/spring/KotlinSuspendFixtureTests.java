package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A suspend function's f$suspendImpl copy of its annotations is not an entry point of its own.
 */
class KotlinSuspendFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("kotlinsuspend");

    @Test
    void aSuspendFunctionIsOneEntryPoint() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:SCHEDULED Jobs.tick", "ingress:KAFKA orders")
                .noneMatch(id -> id.contains("suspendImpl") || id.contains("handler="));
    }
}
