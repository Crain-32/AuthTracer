package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A builder used one statement at a time ({@code b.customer(x); b.card(y); return b.build();}), not chained.
 */
class BuilderStatementsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("builderstatements");

    @Test
    void eachStatementSetsTheBuildersField() {
        assertThat(graph.flows("ingress:GET /receipt").stream()
                .map(flow -> flow.source() + " " + flow.from() + " -> " + flow.to())).containsExactlyInAnyOrder(
                        FieldSource.DIRECT + " field:fixtures.builderstatements.Order.customer"
                                + " -> field:fixtures.builderstatements.Receipt.customer",
                        FieldSource.DIRECT + " field:fixtures.builderstatements.Order.card"
                                + " -> field:fixtures.builderstatements.Receipt.card",
                        FieldSource.DIRECT + " field:fixtures.builderstatements.Order.total"
                                + " -> field:fixtures.builderstatements.Receipt.total");
    }
}
