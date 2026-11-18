package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Getter names as the application's Jackson writes them: Jackson 3 keeps a name whose first two letters are
 * capitals, Jackson 2 lower-cases the leading capitals.
 */
class JacksonNamesFixtureTests {

    private static final String SSN_CHECK = "location:FIELD:fixtures.jacksonnames.Person#getSSN():@PreAuthorize";

    @Test
    void withJackson3OnTheClasspathItsNamesAreUsed() {
        ApplicationGraph graph = FixtureScans.scan("jacksonnames");
        assertThat(requirements(graph, "GET /person")).containsOnlyKeys("", "SSN", "URLValue", "name")
                .containsEntry("SSN", "ROLE_ADMIN").containsEntry("name", "none");
        assertThat(((AuthorizationLocation) graph.node(SSN_CHECK).orElseThrow()).field()).isEqualTo("SSN");
    }

    @Test
    void withJackson2AloneItsNamesAreUsedAndTheCheckGuardsTheFieldItNames() {
        ApplicationGraph graph = FixtureScans.scanWithoutGroups("jacksonnames", "tools.jackson.core");
        assertThat(requirements(graph, "GET /person")).containsOnlyKeys("", "ssn", "urlvalue", "name")
                .containsEntry("ssn", "ROLE_ADMIN");
        assertThat(((AuthorizationLocation) graph.node(SSN_CHECK).orElseThrow()).field()).isEqualTo("ssn");
    }

    @Test
    void springBootTakesJackson2WhenTheApplicationPrefersIt() {
        assertThat(fields(FixtureScans.scan("jacksonnamespreferred"))).containsExactly("ssn");
    }

    private static Map<String, String> requirements(ApplicationGraph graph, String endpoint) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.endpoint().equals(endpoint))
                .collect(Collectors.toMap(Exposure::field, Exposure::requirement));
    }

    private static List<String> fields(ApplicationGraph graph) {
        return Exposures.of(graph).stream().map(Exposure::field).filter(field -> !field.isEmpty()).toList();
    }
}
