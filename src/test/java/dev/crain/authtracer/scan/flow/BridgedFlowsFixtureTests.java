package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A response returned through a generic interface: the call runs javac's bridge, whose summary is the bridged
 * method's, not its own.
 */
class BridgedFlowsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("bridgedflows");

    @Test
    void aCallThroughABridgeCarriesTheBridgedMethodsFlows() {
        assertThat(graph.flows("ingress:GET /accounts/{id}").stream()
                .map(flow -> flow.source() + " " + flow.from() + " -> " + flow.to())).containsExactlyInAnyOrder(
                        FieldSource.DIRECT + " field:fixtures.bridgedflows.Account.owner"
                                + " -> field:fixtures.bridgedflows.AccountView.owner",
                        FieldSource.DIRECT + " field:fixtures.bridgedflows.Account.iban"
                                + " -> field:fixtures.bridgedflows.AccountView.iban");
    }
}
