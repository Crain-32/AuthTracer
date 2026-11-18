package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * An array in a view's model: its element type names it, as Spring's Conventions does, and is what the template's
 * th:each reads.
 */
class ViewArraysFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("viewarrays");

    @Test
    void anUnnamedArrayIsItsElementsList() {
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.endpoint().equals("GET /pets"))
                .extracting(Exposures.Exposure::field).containsExactlyInAnyOrder("", "petList", "petList[].name");
    }
}
