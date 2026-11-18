package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.TreeSet;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class RoleHierarchyFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("roles");

    @Test
    void fromHierarchyIsRecordedOnTheAuthoritySource() {
        assertThat(graph.authoritySource().roleHierarchy()).containsOnlyKeys("ROLE_ADMIN", "ROLE_STAFF", "ROLE_USER");
        assertThat(graph.authoritySource().roleHierarchy().get("ROLE_USER")).containsExactly("ROLE_GUEST");
    }

    @Test
    void requestRulesAdmitHigherRoles() {
        Requirement staff = first("GET /staff/rota").requirement();
        assertThat(staff.authorities()).containsExactly("ROLE_ADMIN", "ROLE_STAFF");
        assertThat(staff.expression()).isEqualTo("hasRole(STAFF)");
    }

    @Test
    void allRolesBecomeOneAnyPerRole() {
        Requirement both = first("GET /both/report").requirement();
        assertThat(both.kind()).isEqualTo(Kind.AND);
        assertThat(both.operands()).extracting(Requirement::authorities).containsExactly(
                new TreeSet<>(List.of("ROLE_AUDITOR")),
                new TreeSet<>(List.of("ROLE_ADMIN", "ROLE_STAFF", "ROLE_USER")));
    }

    @Test
    void newWebExpressionManagersIgnoreTheHierarchy() {
        assertThat(first("GET /legacy/page").requirement().authorities()).containsExactly("ROLE_USER");
    }

    @Test
    void methodSecurityAdmitsHigherRoles() {
        Requirement profile = method("GET /profile").requirement();
        assertThat(profile.kind()).isEqualTo(Kind.OR);
        assertThat(profile.operands().getFirst().authorities())
                .containsExactly("ROLE_ADMIN", "ROLE_STAFF", "ROLE_USER");
        assertThat(profile.operands().get(1).authorities()).containsExactly("profile:read");
        assertThat(method("GET /admin").requirement().authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void builderChainsArePrefixed() {
        ApplicationGraph builder = FixtureScans.scan("rolebuilder");
        assertThat(builder.authoritySource().roleHierarchy().get("ROLE_STAFF"))
                .containsExactly("ROLE_GUEST", "ROLE_USER");
        List<String> path = path(builder, "ingress:GET /guest/welcome");
        AuthorizationLocation guest = (AuthorizationLocation) builder.node(path.getFirst()).orElseThrow();
        assertThat(guest.requirement().authorities()).containsExactly("ROLE_ADMIN", "ROLE_GUEST", "ROLE_STAFF");
    }

    @Test
    void servicesWithoutAHierarchyAreUnchanged() {
        assertThat(FixtureScans.scan("web").authoritySource().roleHierarchy()).isNull();
    }

    private AuthorizationLocation first(String ingress) {
        return (AuthorizationLocation) graph.node(path(graph, "ingress:" + ingress).getFirst()).orElseThrow();
    }

    private AuthorizationLocation method(String ingress) {
        return (AuthorizationLocation) graph.node(path(graph, "ingress:" + ingress).getLast()).orElseThrow();
    }
}
