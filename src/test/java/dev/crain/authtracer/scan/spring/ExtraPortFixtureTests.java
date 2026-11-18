package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class ExtraPortFixtureTests {

    @Test
    void aConnectorTheCodeAddsIsAnotherPort() {
        ApplicationGraph graph = FixtureScans.scan("extraport");
        assertThat(graph.port()).isEqualTo(8443);
        assertThat(graph.additionalPorts()).containsExactly(8090, 9090);
    }

    @Test
    void aPortTheEnvironmentMaySetIsItsDefault() {
        ApplicationGraph graph = FixtureScans.scan("placeholderport");
        assertThat(graph.port()).isEqualTo(8443);
        assertThat(graph.additionalPorts()).containsExactly(9090);
    }
}
