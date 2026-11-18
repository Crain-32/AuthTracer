package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class EgressConcatFixtureTests {

    @Test
    void aFieldInitializedBaseUrlAndARelativePathWithAQuery() {
        ApplicationGraph graph = FixtureScans.scan("egressconcat");
        assertThat(graph.nodes()).filteredOn(Egress.class::isInstance).map(Egress.class::cast).singleElement()
                .satisfies(egress -> {
                    assertThat(egress.uriTemplate()).isEqualTo("/pets/visits");
                    assertThat(egress.baseUrl()).isEqualTo("http://visits-service");
                });
    }
}
