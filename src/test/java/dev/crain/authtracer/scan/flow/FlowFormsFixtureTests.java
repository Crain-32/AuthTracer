package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The forms a value takes on its way into a response (negation, an array's length or element, instanceof, a public
 * field, a builder that reads what it set, a wrapper), and the properties Jackson writes.
 */
class FlowFormsFixtureTests {

    private static final String ACCOUNT = "field:fixtures.flowforms.Account.";

    private final ApplicationGraph graph = FixtureScans.scan("flowforms");

    @Test
    void operatorsComputeAndAnArraysElementIsTheArrays() {
        assertThat(into("/figures", "Figures.debt")).containsExactly(flow(ACCOUNT + "balance", FieldSource.COMPUTED));
        assertThat(into("/figures", "Figures.tagCount")).containsExactly(flow(ACCOUNT + "tags", FieldSource.COMPUTED));
        assertThat(into("/figures", "Figures.textNote")).containsExactly(flow(ACCOUNT + "note", FieldSource.COMPUTED));
        assertThat(into("/figures", "Figures.firstTag")).containsExactly(flow(ACCOUNT + "tags", FieldSource.DIRECT));
        // A map's default is a value it may give; the array asList wraps holds its elements.
        assertThat(into("/figures", "Figures.names")).containsExactly(flow(ACCOUNT + "owner", FieldSource.DIRECT));
        // A library method's reference computes.
        assertThat(into("/figures", "Figures.trimmed")).containsExactly(flow(ACCOUNT + "tags", FieldSource.COMPUTED));
    }

    @Test
    void aPublicFieldOfAnObjectBuiltHereIsWhatItWasSetTo() {
        assertThat(into("/label", "Label.text")).containsExactly(flow(ACCOUNT + "owner", FieldSource.DIRECT));
    }

    @Test
    void aWrapperALibraryBuildsAroundTheBodyIsTheBody() {
        assertThat(into("/entity", "Label.text")).containsExactly(flow(ACCOUNT + "owner", FieldSource.DIRECT));
    }

    @Test
    void aBuilderReadsWhatItSetAndBuildsWithItsOwnArguments() {
        assertThat(into("/statement", "Statement.owner")).containsExactly(flow(ACCOUNT + "owner", FieldSource.DIRECT));
        assertThat(into("/statement", "Statement.heading"))
                .containsExactly(flow(ACCOUNT + "owner", FieldSource.COMPUTED));
        assertThat(into("/statement", "Statement.period"))
                .containsExactly(flow(ACCOUNT + "balance", FieldSource.COMPUTED));
    }

    @Test
    void aHandlersGenericReturnTypeIsReadWhateverItsParameters() {
        assertThat(response("/converted")).isEqualTo(new Payload("fixtures.flowforms.Label", true));
        assertThat(response("/labels")).isEqualTo(new Payload("fixtures.flowforms.Label", true));
    }

    @Test
    void aMethodReferenceAMethodReturnsIsApplied() {
        assertThat(into("/mapped", "Label.text")).contains(flow(ACCOUNT + "owner", FieldSource.COMPUTED));
    }

    @Test
    void thePropertiesJacksonWrites() {
        // Inherited, read-only and un-ignored ones are written; the one ignored by its JSON name isn't.
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.endpoint().equals("GET /profile"))
                .extracting(Exposures.Exposure::field).containsExactlyInAnyOrder("", "name", "id", "email", "tags",
                        "petsByName", "petsByName.*.name", "favourite", "favourite.name", "current", "current.name");
        assertThat(javaType("ProfileView.tags")).isEqualTo("java.lang.String[]");
        assertThat(javaType("ProfileView.petsByName")).isEqualTo("fixtures.flowforms.Pet{}");
        // An Optional and an AtomicReference are written as the value they hold.
        assertThat(javaType("ProfileView.favourite")).isEqualTo("fixtures.flowforms.Pet");
        assertThat(javaType("ProfileView.current")).isEqualTo("fixtures.flowforms.Pet");
    }

    private Payload response(String route) {
        return ((Ingress) graph.node("ingress:GET " + route).orElseThrow()).response();
    }

    private String javaType(String field) {
        return ((Field) graph.node("field:fixtures.flowforms." + field).orElseThrow()).javaType();
    }

    private List<String> into(String route, String field) {
        return graph.flows("ingress:GET " + route).stream()
                .filter(flow -> flow.to().equals("field:fixtures.flowforms." + field))
                .map(flow -> flow(flow.from(), flow.source())).toList();
    }

    private static String flow(String from, FieldSource source) {
        return source + " " + from;
    }
}
