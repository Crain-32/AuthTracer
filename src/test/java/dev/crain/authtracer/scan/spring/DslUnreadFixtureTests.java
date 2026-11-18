package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A rule AuthTracer can't fully read is still a rule: the request doesn't fall through to the next one.
 */
class DslUnreadFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("dslunread");

    @Test
    void aNegatedRuleIsTheNegationOfItsRequirement() {
        Requirement internal = rule(graph, "GET /internal/report").requirement();
        assertThat(internal.kind()).isEqualTo(Requirement.Kind.NOT);
        assertThat(internal.operands()).singleElement().satisfies(operand ->
                assertThat(operand.authorities()).containsExactly("ROLE_PARTNER"));
    }

    @Test
    void aPathVariableComparedWithTheCallerIsAnExpression() {
        assertThat(rule(graph, "GET /users/{id}/orders").requirement()).satisfies(requirement -> {
            assertThat(requirement.kind()).isEqualTo(Requirement.Kind.EXPRESSION);
            assertThat(requirement.expression()).startsWith("hasVariable(id).equalTo(");
        });
    }

    @Test
    void aRoleThatIsNotAConstantKeepsItsRuleAndIsReported() {
        assertThat(rule(graph, "GET /admin/users").requirement()).satisfies(requirement -> {
            assertThat(requirement.kind()).isEqualTo(Requirement.Kind.EXPRESSION);
            assertThat(requirement.expression()).isEqualTo("hasRole(?)");
        });
        assertThat(rule(graph, "GET /public").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
            assertThat(finding.message()).contains("hasRole(?)").contains("/admin/**");
        });
    }

    @Test
    void rulesSetInAHelperMethodOrByAReturnedCustomizerAreRead() {
        assertThat(rule(graph, "GET /api/items").requirement().authorities()).containsExactly("ROLE_API");
        assertThat(rule(graph, "GET /ops/status").requirement().authorities()).containsExactly("ROLE_OPS");
    }
}
