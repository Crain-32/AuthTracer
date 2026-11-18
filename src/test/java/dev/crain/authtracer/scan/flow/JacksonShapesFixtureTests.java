package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The properties Jackson finds beyond getX(), and the types it writes some other way, which are reported.
 */
class JacksonShapesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jacksonshapes");

    @Test
    void aMarkedMethodOfAnyNameIsAPropertyAndIsXIsOneOfABooleanOnly() {
        assertThat(fields("fixtures.jacksonshapes.AccountView")).containsExactlyInAnyOrder("maskedIban as iban",
                "owner as holder", "active as active");
    }

    @Test
    void privateFieldsAreWrittenWithFieldVisibilityAny() {
        assertThat(fields("fixtures.jacksonshapes.Ledger")).containsExactly("entries as entries");
    }

    @Test
    void aTypeJacksonWritesSomeOtherWayIsReported() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).containsExactlyInAnyOrder(
                        "fixtures.jacksonshapes.Token is in a response, and @JsonValue writes it as one value: its"
                                + " fields in the graph are its properties, which may not be what Jackson writes",
                        "fixtures.jacksonshapes.Extra is in a response, and @JsonAnyGetter adds the entries of a map"
                                + " to it: its fields in the graph are its properties, which may not be what Jackson"
                                + " writes",
                        "fixtures.jacksonshapes.Instrument is in a response, and @JsonSubTypes writes its subtypes'"
                                + " properties too: its fields in the graph are its properties, which may not be what"
                                + " Jackson writes");
    }

    private List<String> fields(String owner) {
        return graph.nodes(Field.class).stream().filter(field -> field.owner().equals(owner))
                .map(field -> field.name() + " as " + field.jsonName()).toList();
    }
}
