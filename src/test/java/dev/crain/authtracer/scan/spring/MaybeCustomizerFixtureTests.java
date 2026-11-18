package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0111: the rules of a customizer bean that may not be made may take their requests, or leave them to the
 * rules after them.
 */
class MaybeCustomizerFixtureTests {

    @Test
    void aCustomizersRuleUnderAProfileTheConfigurationDoesntActivateMayMatchFirst() {
        ApplicationGraph graph = FixtureScans.scan("maybecustomizer");
        AuthorizationLocation report = FixtureScans.rule(graph, "GET /admin/report");
        assertThat(report.id()).startsWith("location:SPLIT:");
        assertThat(report.mechanism()).endsWith("(a customizer bean that may not be made may match first)");
        assertThat(report.requirement().operands()).flatExtracting(Requirement::authorities)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_STAFF");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("fixtures.maybecustomizer.StrictRules is only a bean when profile strict is"
                                + " active")
                        .contains("its bean adminOnly (the requests its rules match get them or the rules after"
                                + " them, whichever asks less)"));
    }
}
