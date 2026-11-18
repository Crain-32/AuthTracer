package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Maps whose values are application objects: Jackson writes each value's fields under its key.
 */
class JsonMapsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jsonmaps");

    @Test
    void aMapsValuesFieldsAreInTheResponseUnderAnyKey() {
        assertThat(exposures().stream().map(Exposure::field).filter(field -> !field.isEmpty()))
                .containsExactlyInAnyOrder("petsByName", "petsByName.*.name", "petsByName.*.chip", "sorted",
                        "sorted.*.name", "sorted.*.chip", "notes", "byKind");
        assertThat(field("petsByName").javaType()).isEqualTo("fixtures.jsonmaps.PetView{}");
        assertThat(field("notes").javaType()).isEqualTo("java.util.Map");
    }

    @Test
    void whatAMapsValuesAreBuiltFromFlowsIntoTheirFields() {
        assertThat(exposure("petsByName.*.chip").lineage()).extracting(Flow::from)
                .containsExactly("jsonmaps/field:fixtures.jsonmaps.Pet.chip");
    }

    private Field field(String name) {
        return graph.nodes(Field.class).stream().filter(field -> field.id().equals(
                "field:fixtures.jsonmaps.ShelterView." + name)).findFirst().orElseThrow();
    }

    private Exposure exposure(String field) {
        return exposures().stream().filter(exposure -> exposure.field().equals(field)).findFirst().orElseThrow();
    }

    private List<Exposure> exposures() {
        return Exposures.of(graph).stream().filter(exposure -> exposure.endpoint().equals("GET /shelter")).toList();
    }
}
