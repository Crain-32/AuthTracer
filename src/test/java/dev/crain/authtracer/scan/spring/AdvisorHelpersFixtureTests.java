package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0092: advisor beans built by helpers, ordered with {@code setOrder(..)}, given the RoleHierarchy, or that
 * AuthTracer can't read; and {@code spring.aop.auto=false}.
 */
class AdvisorHelpersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("advisorhelpers");

    @Test
    void anAdvisorAHelperBuildsIsRead() {
        AuthorizationLocation read = checks("GET /ledger").getFirst();
        assertThat(read.mechanism()).isEqualTo("Advisor guardRead()");
        assertThat(read.requirement().authorities()).containsExactly("ROLE_CLERK");
    }

    @Test
    void aManagerGivenTheRoleHierarchyIsWidenedByIt() {
        assertThat(checks("POST /ledger/close").getFirst().requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_OPS", "ROLE_ADMIN");
        // Spring's factories' managers have no hierarchy of their own.
        assertThat(checks("POST /ledger/reopen").getFirst().requirement().authorities())
                .containsExactly("ROLE_OPS");
        AuthorizationLocation archive = checks("POST /ledger/archive").getFirst();
        assertThat(archive.mechanism()).isEqualTo("@RolesAllowed");
        assertThat(archive.requirement().authorities()).containsExactlyInAnyOrder("ROLE_OPS", "ROLE_ADMIN");
    }

    @Test
    void setOrderPlacesAnAnnotationAdvisorAmongSpringsInterceptors() {
        assertThat(checks("POST /ledger/approve")).extracting(AuthorizationLocation::mechanism)
                .containsExactly("@Secured", "@PreAuthorize");
    }

    @Test
    void anAdvisorAuthTracerCantReadIsAnOpaqueConfiguration() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anyMatch(message -> message.contains("wrapped()")
                        && message.contains("builds an advisor AuthTracer can't read"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement().asString().doesNotContain("guardRead()",
                        "guardClose(", "guardReopen()", "preAuthorize()", "jsr250(");
    }

    @Test
    void springAopAutoFalseLeavesNoAutoProxyCreatorForAdvisorBeans() {
        ApplicationGraph off = FixtureScans.scan("bootadvisorsoff");
        assertThat(path(off, "ingress:GET /stock")).noneMatch(id -> off.node(id).orElseThrow()
                instanceof AuthorizationLocation location && location.mechanism().startsWith("Advisor"));
        assertThat(off.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).hasSize(2)
                .allMatch(message -> message.contains("spring.aop.auto=false turns Spring Boot's off"))
                .anyMatch(message -> message.contains("guardCount()"))
                .anyMatch(message -> message.contains("StockAdvisor"));
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST).toList();
    }
}
