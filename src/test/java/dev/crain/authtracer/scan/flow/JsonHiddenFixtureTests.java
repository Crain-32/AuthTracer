package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * What Jackson leaves out of a response isn't exposed.
 */
class JsonHiddenFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jsonhidden");

    @Test
    void ignoredWriteOnlyAndClassLevelIgnoredPropertiesAreNotExposed() {
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals("ingress:GET /account"))
                .extracting(Exposures.Exposure::field).filteredOn(field -> !field.isEmpty())
                .containsExactlyInAnyOrder("username", "mail");
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals("ingress:GET /card"))
                .extracting(Exposures.Exposure::field).filteredOn(field -> !field.isEmpty())
                .containsExactly("last4");
    }

    @Test
    void propertiesIgnoredOnReadOnlyAreStillWritten() {
        assertThat(fields("ingress:GET /session")).containsExactlyInAnyOrder("user", "token");
        // A name listed twice is still one ignored property.
        assertThat(fields("ingress:GET /device")).containsExactly("name");
    }

    private List<String> fields(String ingress) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.ingress().equals(ingress))
                .map(Exposures.Exposure::field).filter(field -> !field.isEmpty()).toList();
    }
}
