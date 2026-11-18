package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0027: a Split asks for its parts' requirements as their own policies expand them.
 */
class SplitPolicyFixtureTests {

    @Test
    void aSplitOfPrePostChecksTakesPrePostsHierarchy() {
        ApplicationGraph graph = FixtureScans.scan("splitpolicy");
        AuthorizationLocation split = (AuthorizationLocation) graph.node(
                "location:SPLIT:fixtures.splitpolicy.ReportController#report(boolean)").orElseThrow();
        assertThat(split.requirement().kind()).isEqualTo(Requirement.Kind.OR);
        // The pre/post factory's ROLE_LEAD > ROLE_STAFF, not the RoleHierarchy bean's ROLE_ADMIN > ROLE_STAFF.
        assertThat(split.requirement().operands()).extracting(Requirement::authorities).map(Set::copyOf)
                .containsExactlyInAnyOrder(Set.of("ROLE_AUDITOR"), Set.of("ROLE_STAFF", "ROLE_LEAD"));
    }
}
