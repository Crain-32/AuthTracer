package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.DiffReport;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.mutation.MutationScans;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Rules set through helper methods and customizers: the ones AuthTracer can follow are read, and the ones it can't
 * (an abstract method, helpers nested too deep, a customizer held in a field) are one opaque rule for every request
 * of the chain, reported, rather than no rule.
 */
class DslHelpersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("dslhelpers");

    @Test
    void rulesATemplateMethodLeavesToASubclassAreOpaque() {
        AuthorizationLocation api = rule(graph, "GET /api/items");
        assertThat(api.requirement().kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(api.requirement().expression()).isEqualTo("rules set in apiRules(..)");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("BaseSecurityConfig#api(", "rules set in apiRules(..)"));
    }

    @Test
    void helpersNestedDeeperThanAreFollowedAreOpaque() {
        assertThat(rule(graph, "GET /admin/users").requirement().expression()).isEqualTo("rules set in adminRules(..)");
    }

    /**
     * Decision 0106: an opaque rule carries a digest of the configuration it stands for, so changing the rules
     * AuthTracer can't read needs review rather than passing.
     */
    @Test
    void changingRulesItCantReadNeedsReview() {
        for (String change : List.of("adminRules(): .anyRequest().hasRole(\"ADMIN\") to permitAll()",
                "apiRules(): .anyRequest().hasRole(\"API\") to authenticated()",
                "DslHelpersConfig: .anyRequest().hasRole(\"REPORTS\") to permitAll()")) {
            MutationScans.Mutated mutated = MutationScans.mutate("dslhelpers", change);
            assertThat(mutated.diff().changes()).as(change).filteredOn(diff -> diff.field().isEmpty())
                    .filteredOn(diff -> diff.kind() == DiffReport.Kind.CHANGED).isNotEmpty()
                    .allSatisfy(diff -> assertThat(diff.message()).contains("AuthTracer can't read changed"));
        }
        assertThat(rule(graph, "GET /admin/users").requirement().code()).isNotBlank();
        // The rules it reads compare as they did: a digest is for the code an opaque rule stands for.
        assertThat(rule(graph, "GET /health").requirement().code()).isNull();
    }

    @Test
    void aCustomizerHeldInAFieldIsOpaque() {
        assertThat(rule(graph, "GET /reports/daily").requirement().expression())
                .isEqualTo("authorizeHttpRequests(customizer)");
    }

    @Test
    void aHelperGivenTheRegistryAddsItsRules() {
        assertThat(rule(graph, "GET /health").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void pathsInjectedFromPropertiesMayMatchFirst() {
        AuthorizationLocation home = rule(graph, "GET /home");
        assertThat(home.id()).startsWith("location:SPLIT:");
        assertThat(home.requirement().kind()).isEqualTo(Kind.OR);
        assertThat(home.requirement().operands()).extracting(operand -> operand.kind())
                .containsExactly(Kind.PERMIT_ALL, Kind.AUTHENTICATED);
    }
}
