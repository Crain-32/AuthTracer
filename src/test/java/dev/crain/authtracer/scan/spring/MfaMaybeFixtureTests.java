package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0111: a factory bean that may not be made adds no factors to the rules (their weaker reading).
 */
class MfaMaybeFixtureTests {

    @Test
    void aFactoryUnderAProfileTheConfigurationDoesntActivateAddsNoFactor() {
        ApplicationGraph graph = FixtureScans.scan("mfamaybe");
        Requirement home = FixtureScans.rule(graph, "GET /home").requirement();
        assertThat(home.kind()).isEqualTo(Requirement.Kind.ANY_AUTHORITY);
        assertThat(home.authorities()).containsExactly("ROLE_STAFF");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("fixtures.mfamaybe.StrictFactors is only a bean when profile strict is active")
                        .contains("its bean authorizationManagerFactory (the rules it builds are shown without the"
                                + " factors it adds)"));
    }
}
