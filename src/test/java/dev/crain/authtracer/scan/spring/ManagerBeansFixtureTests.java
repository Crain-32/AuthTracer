package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0037's manager beans: an AuthorizationManager parameter of the chain method is the @Bean method of its
 * name, read for the manager it returns; one AuthTracer can't read is an opaque access(..) rule.
 */
class ManagerBeansFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("managerbeans");

    @Test
    void theBeanOfTheParametersNameIsRead() {
        assertThat(rule(graph, "GET /ops/status").requirement().authorities()).containsExactly("ROLE_OPS");
    }

    @Test
    void aBeanThatIsNotBuiltFromTheFactoriesIsDecidedByTheClassItCreates() {
        Requirement trading = rule(graph, "GET /trading/orders").requirement();
        assertThat(trading.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(trading.expression()).isEqualTo("access(AuthorizationManager)");
        assertThat(trading.decidedBy().className()).isEqualTo("fixtures.managerbeans.BusinessHours");
    }

    @Test
    void aComponentNoBeanMethodDeclaresIsFoundByItsName() {
        assertThat(rule(graph, "GET /office/printers").requirement().decidedBy().className())
                .isEqualTo("fixtures.managerbeans.OfficeNetwork");
    }
}
