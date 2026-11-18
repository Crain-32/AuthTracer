package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Functions a value may be: each one chosen on a branch is applied.
 */
class FlowFunctionsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("flowfunctions");

    @Test
    void twoMethodReferencesChosenOnBranchesAreBothApplied() {
        assertThat(graph.flows("ingress:GET /labels")).filteredOn(flow -> flow.to().equals(
                "field:fixtures.flowfunctions.Label.text")).extracting(Flow::from)
                .containsExactlyInAnyOrder("field:fixtures.flowfunctions.Account.owner",
                        "field:fixtures.flowfunctions.Account.iban");
    }

    @Test
    void aLambdaOverValuesAFunctionMadeReadsWhatTheyWereMadeFrom() {
        assertThat(graph.flows("ingress:GET /cards")).extracting(Flow::from, Flow::to, Flow::source)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("field:fixtures.flowfunctions.Account.iban",
                        "field:fixtures.flowfunctions.Card.title", dev.crain.authtracer.graph.FieldSource.COMPUTED));
    }
}
