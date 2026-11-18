package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import org.junit.jupiter.api.Test;

/**
 * Which parts of a requirement are a {@code hasPermission(..)} call of their own.
 */
class PermissionEvaluatorsTests {

    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"));

    @Test
    void onlyAWholeHasPermissionCallIsOne() {
        assertThat(PermissionEvaluators.mentionsHasPermission(Requirement.expression("hasPermission(#id, 'read')")))
                .isTrue();
        assertThat(PermissionEvaluators.mentionsHasPermission(
                Requirement.expression("hasPermission(#id, 'read') == false"))).isFalse();
        assertThat(PermissionEvaluators.mentionsHasPermission(Requirement.expression("hasPermission(#id, 'read'")))
                .isFalse();
        assertThat(PermissionEvaluators.mentionsHasPermission(Requirement.expression("@acl.check(#id)"))).isFalse();
        assertThat(PermissionEvaluators.mentionsHasPermission(ADMIN)).isFalse();
    }

    @Test
    void withoutAnEvaluatorEachCallDeniesAndTheRestStays() {
        Requirement either = Requirement.or(List.of(ADMIN, Requirement.expression("hasPermission(#id, 'read')")));
        Requirement denied = PermissionEvaluators.denied(either);
        assertThat(denied.operands()).extracting(Requirement::kind).containsExactly(Kind.ANY_AUTHORITY, Kind.DENY_ALL);
        assertThat(PermissionEvaluators.denied(Requirement.not(ADMIN))).isEqualTo(Requirement.not(ADMIN));
        assertThat(PermissionEvaluators.denied(Requirement.expression("@acl.check(#id)")).kind())
                .isEqualTo(Kind.EXPRESSION);
        assertThat(PermissionEvaluators.denied(ADMIN)).isEqualTo(ADMIN);
    }
}
