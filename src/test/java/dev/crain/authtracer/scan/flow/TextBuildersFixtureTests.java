package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A value built a statement at a time with the library's mutators keeps where its parts came from.
 */
class TextBuildersFixtureTests {

    private static final String EMPLOYEE = "field:fixtures.textbuilders.Employee.";

    private final ApplicationGraph graph = FixtureScans.scan("textbuilders");

    @Test
    void textAppendedOneStatementAtATimeIsComputedFromEachPart() {
        assertThat(into("Card.label")).containsExactlyInAnyOrder(EMPLOYEE + "ssn", EMPLOYEE + "name");
        assertThat(into("Card.joined")).containsExactly(EMPLOYEE + "ssn");
    }

    @Test
    void elementsAddedByTheLibrarysOtherMutatorsAreTheCollections() {
        assertThat(into("Card.names")).containsExactlyInAnyOrder(EMPLOYEE + "ssn", EMPLOYEE + "name");
        assertThat(into("Card.byName")).containsExactly(EMPLOYEE + "ssn");
    }

    private List<String> into(String field) {
        return graph.flows("ingress:GET /card").stream()
                .filter(flow -> flow.to().equals("field:fixtures.textbuilders." + field))
                .map(flow -> flow.from()).distinct().toList();
    }
}
