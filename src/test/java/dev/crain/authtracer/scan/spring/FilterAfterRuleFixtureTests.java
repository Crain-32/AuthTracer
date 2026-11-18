package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0071: a filter that authenticates after the AuthorizationFilter is a way in for the checks after it only;
 * the request rules have decided by then, for a caller who hadn't signed in.
 */
class FilterAfterRuleFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("filterafterrule");

    @Test
    void aFilterAfterTheRuleSaysSoInItsWayIn() {
        assertThat(graph.authoritySource().detail()).isEqualTo("HTTP Basic, Custom filter AuditorFilter (after the"
                + " AuthorizationFilter; UsernamePasswordAuthenticationToken; authorities ROLE_AUDITOR; from what the"
                + " request carries), Custom filter ServiceKeyFilter (after the AuthorizationFilter;"
                + " UsernamePasswordAuthenticationToken; authorities ROLE_SERVICE; from what the request carries)");
    }

    @Test
    void aFilterAfterTheRuleIsAFindingAtItsCode() {
        List<Finding> late = graph.findings().stream()
                .filter(finding -> finding.kind() == Finding.Kind.AUTHORITIES_IN_CODE).toList();
        assertThat(late).extracting(finding -> finding.location().className())
                .containsExactlyInAnyOrder("fixtures.filterafterrule.AuditorFilter",
                        "fixtures.filterafterrule.ServiceKeyFilter");
        assertThat(late).extracting(Finding::message).allSatisfy(message -> assertThat(message)
                .contains(" authenticates after the AuthorizationFilter: the request rules have already decided, for"
                        + " a caller who hadn't signed in, so what it sets counts only for the checks after them"));
    }

    @Test
    void aFilterBeforeTheRuleIsAWayInWithoutAFinding() {
        ApplicationGraph live = FixtureScans.scan("filterauthlive");
        assertThat(live.authoritySource().detail()).doesNotContain("after the AuthorizationFilter");
        assertThat(live.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.AUTHORITIES_IN_CODE);
    }
}
