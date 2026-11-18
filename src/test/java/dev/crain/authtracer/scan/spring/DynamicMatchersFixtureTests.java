package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0051: patterns that aren't constants may match any request, so the rules and chains after them may not
 * apply; each is an OPAQUE_CONFIG finding.
 */
class DynamicMatchersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("dynamicmatchers");

    @Test
    void aSecurityMatcherThatIsntAConstantMayTakeTheRequest() {
        AuthorizationLocation check = FixtureScans.rule(graph, "GET /orders");
        assertThat(check.id()).startsWith("location:SPLIT:").contains(":or-chains:");
        assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.OR);
        assertThat(check.requirement().operands()).extracting(Requirement::kind)
                .contains(Requirement.Kind.ANY_AUTHORITY);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("DynamicMatchersApp#internal").contains("a pattern that isn't a constant"));
    }

    @Test
    void aRuleWithAPatternThatIsntAConstantMayMatchFirst() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("The rule /public, a pattern that isn't a"
                        + " constant (requires permitAll)"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule a pattern that isn't a constant"
                        + " (requires hasRole(WRITER))"));
    }
}
