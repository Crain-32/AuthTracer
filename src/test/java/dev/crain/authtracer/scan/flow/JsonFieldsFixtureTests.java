package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The fields Jackson writes as properties, and what fills them.
 */
class JsonFieldsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jsonfields");

    @Test
    void publicFieldsAndFieldsJsonPropertyNamesAreWritten() {
        assertThat(exposures().stream().map(Exposure::field).filter(field -> !field.isEmpty()))
                .containsExactlyInAnyOrder("owner", "iban_number", "label");
    }

    @Test
    void aPublicFieldOfAnObjectBuiltHereHoldsWhatIsAssignedToIt() {
        assertThat(lineage("owner")).extracting(Flow::from, Flow::source)
                .containsExactly(org.assertj.core.groups.Tuple.tuple(
                        "jsonfields/field:fixtures.jsonfields.Account.owner", FieldSource.DIRECT));
        assertThat(lineage("iban_number")).extracting(Flow::from)
                .containsExactly("jsonfields/field:fixtures.jsonfields.Account.iban");
    }

    private List<Flow> lineage(String field) {
        return exposures().stream().filter(exposure -> exposure.field().equals(field)).findFirst().orElseThrow()
                .lineage();
    }

    private List<Exposure> exposures() {
        return Exposures.of(graph).stream().filter(exposure -> exposure.endpoint().equals("GET /account")).toList();
    }
}
