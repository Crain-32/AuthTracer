package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0038: hasPermission(..) needs a PermissionEvaluator that reaches method security.
 */
class PermissionEvaluatorFixtureTests {

    @Test
    void enableMethodSecurityIgnoresAPermissionEvaluatorBean() {
        ApplicationGraph graph = FixtureScans.scan("permissions");
        Requirement write = check(graph, "GET /documents/{id}/edit").requirement();
        assertThat(write.kind()).isEqualTo(Requirement.Kind.DENY_ALL);
        // Written as it was, so traces still match it.
        assertThat(write.expression()).isEqualTo("hasPermission(#id,'Document','write')");
        Requirement read = check(graph, "GET /documents/{id}").requirement();
        assertThat(read.kind()).isEqualTo(Requirement.Kind.OR);
        assertThat(read.operands()).extracting(Requirement::kind)
                .containsExactly(Requirement.Kind.DENY_ALL, Requirement.Kind.ANY_AUTHORITY);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .hasSize(2).extracting(Finding::message).allMatch(message -> message.contains("DenyAllPermissionEvaluator"));
    }

    @Test
    void anExpressionHandlerBeanOrTheLegacyAnnotationUsesTheEvaluator() {
        for (String fixture : new String[] {"permissionhandler", "permissionlegacy"}) {
            ApplicationGraph graph = FixtureScans.scan(fixture);
            assertThat(check(graph, "GET /documents/{id}/edit").requirement().kind())
                    .as(fixture).isEqualTo(Requirement.Kind.EXPRESSION);
            assertThat(graph.findings()).as(fixture).noneMatch(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED);
        }
    }

    @Test
    void anEvaluatorComponentOrTheApplicationsOwnHandlerReachesMethodSecurity() {
        for (String fixture : new String[] {"permissioncomponent", "permissionhandlerclass", "permissionhandlernew"}) {
            ApplicationGraph graph = FixtureScans.scan(fixture);
            assertThat(check(graph, "GET /documents/{id}/edit").requirement().kind())
                    .as(fixture).isEqualTo(Requirement.Kind.EXPRESSION);
            assertThat(graph.findings()).as(fixture).noneMatch(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED);
        }
    }

    @Test
    void aHandlerBeanNotGivenTheEvaluatorStillDenies() {
        ApplicationGraph graph = FixtureScans.scan("permissionhandlerunset");
        assertThat(check(graph, "GET /documents/{id}/edit").requirement().kind())
                .isEqualTo(Requirement.Kind.DENY_ALL);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED).hasSize(1);
    }

    @Test
    void withoutAnEvaluatorEachHasPermissionDeniesWhereverItIs() {
        ApplicationGraph graph = FixtureScans.scan("permissionnone");
        Requirement write = check(graph, "GET /documents/{id}/edit").requirement();
        assertThat(write.operands()).extracting(Requirement::kind)
                .containsExactly(Requirement.Kind.AND, Requirement.Kind.DENY_ALL);
        assertThat(write.operands().getFirst().operands()).extracting(Requirement::kind)
                .containsExactly(Requirement.Kind.ANY_AUTHORITY, Requirement.Kind.AUTHENTICATED);
        // Decision 0092: its negation admits everyone.
        Requirement read = check(graph, "GET /documents/{id}").requirement();
        assertThat(read.kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(read.expression()).isEqualTo("!hasPermission(#id, 'Document', 'archived')");
        // Compared with true, it is hasPermission(..) itself.
        assertThat(check(graph, "GET /documents/{id}/preview").requirement().kind())
                .isEqualTo(Requirement.Kind.DENY_ALL);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).hasSize(2).anyMatch(message -> message.contains("preview"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_GRANTED)
                .extracting(Finding::message).singleElement().asString().contains("Documents#read", "admits everyone");
    }

    @Test
    void anEvaluatorFromItsBeanMethodDecidesTheFormItOverridesAndOnlyThat() {
        ApplicationGraph graph = FixtureScans.scan("permissionfactory");
        Requirement read = check(graph, "GET /projects/{id}").requirement();
        assertThat(read.authorities()).containsExactly("ROLE_MEMBER");
        assertThat(read.decidedBy().method()).isEqualTo("hasPermission(org.springframework.security.core"
                + ".Authentication,java.lang.Object,java.lang.Object)");
        // The id form is DenyAllPermissionEvaluator's, which AuthTracer doesn't read: not the target form's.
        Requirement write = check(graph, "GET /projects/{id}/write").requirement();
        assertThat(write.kind()).isEqualTo(Requirement.Kind.EXPRESSION);
        assertThat(write.authorities()).isEmpty();
        assertThat(write.decidedBy().className()).isEqualTo("fixtures.permissionfactory.ProjectPermissions");
        assertThat(write.decidedBy().method()).isNull();
        // Beside an expression it doesn't decide.
        assertThat(check(graph, "GET /projects/{id}/archive").requirement().operands())
                .extracting(Requirement::kind).containsExactly(Requirement.Kind.ANY_AUTHORITY,
                        Requirement.Kind.EXPRESSION);
    }

    private static AuthorizationLocation check(ApplicationGraph graph, String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals("@PreAuthorize")).findFirst().orElseThrow();
    }
}
