package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A handler's @JsonView limits what its response exposes.
 */
class JsonViewFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jsonviews");

    @Test
    void eachHandlerExposesItsViewsFields() {
        assertThat(fields("ingress:GET /employees/summary")).containsExactly("name");
        // Detail extends Summary, so it has both.
        assertThat(fields("ingress:GET /employees/detail")).containsExactlyInAnyOrder("name", "salary");
        // Without a view, everything is written.
        assertThat(fields("ingress:GET /employees/raw")).containsExactlyInAnyOrder("name", "salary", "ssn");
    }

    private List<String> fields(String ingress) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.ingress().equals(ingress))
                .map(Exposures.Exposure::field).filter(field -> !field.isEmpty()).toList();
    }
}
