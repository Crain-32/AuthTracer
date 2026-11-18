package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * ROLE-01 and ROLE-02: a RoleHierarchy and a GrantedAuthorityDefaults bean that aren't built from constants are
 * reported, and role checks are shown with ROLE_ and no hierarchy.
 */
class RoleFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("roleforms");

    @Test
    void roleChecksAreShownAsWritten() {
        Requirement staff = rule(graph, "GET /staff/rota").requirement();
        assertThat(staff.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(staff.authorities()).containsExactly("ROLE_STAFF", "ROLE_TRAINED");
    }

    @Test
    void theHierarchyAndThePrefixAreReported() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("The RoleHierarchy bean"
                        + " fixtures.roleforms.RoleFormsConfig#roleHierarchy(java.lang.String) is not built from"
                        + " constants"))
                .anySatisfy(message -> assertThat(message).startsWith("The GrantedAuthorityDefaults bean"
                        + " fixtures.roleforms.RoleFormsConfig#grantedAuthorityDefaults(java.lang.String) does not set"
                        + " its role prefix from a constant"));
    }
}
