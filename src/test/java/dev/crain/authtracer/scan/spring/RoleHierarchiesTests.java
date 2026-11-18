package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Clauses;
import dev.crain.authtracer.diff.Clauses.Comparison;
import dev.crain.authtracer.graph.Requirement;
import org.junit.jupiter.api.Test;

class RoleHierarchiesTests {

    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"))
            .withSource("hasRole(ADMIN)");

    @Test
    void reachIsTransitive() {
        RoleHierarchies hierarchy = RoleHierarchies.parse("ROLE_OWNER > ROLE_ADMIN\nROLE_ADMIN > ROLE_USER");
        assertThat(hierarchy.expand(Requirement.anyAuthority(List.of("ROLE_USER"))).authorities())
                .containsExactly("ROLE_ADMIN", "ROLE_OWNER", "ROLE_USER");
    }

    @Test
    void cyclesTerminate() {
        RoleHierarchies hierarchy = RoleHierarchies.parse("ROLE_A > ROLE_B\nROLE_B > ROLE_A");
        assertThat(hierarchy.expand(Requirement.anyAuthority(List.of("ROLE_A"))).authorities())
                .containsExactly("ROLE_A", "ROLE_B");
    }

    @Test
    void aRoleThatNowImpliesAdminWeakensAdminChecks() {
        Requirement before = RoleHierarchies.parse("ROLE_ADMIN > ROLE_USER").expand(ADMIN);
        Requirement after = RoleHierarchies.parse("ROLE_ADMIN > ROLE_USER\nROLE_INTERN > ROLE_ADMIN").expand(ADMIN);

        assertThat(after.expression()).isEqualTo("hasRole(ADMIN)");
        assertThat(Clauses.compare(Clauses.of(List.of(before)), Clauses.of(List.of(after))))
                .isEqualTo(Comparison.WEAKER);
    }

    @Test
    void nonAuthorityRequirementsAreUntouched() {
        RoleHierarchies hierarchy = RoleHierarchies.parse("ROLE_ADMIN > ROLE_USER");
        Requirement expression = Requirement.expression("#id == principal.id");
        assertThat(hierarchy.expand(expression)).isSameAs(expression);
        assertThat(RoleHierarchies.NONE.expand(ADMIN)).isSameAs(ADMIN);
    }
}
