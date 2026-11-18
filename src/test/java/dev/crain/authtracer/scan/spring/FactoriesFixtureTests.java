package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class FactoriesFixtureTests {

    @Test
    void aGenericFactoryReplacesTheHierarchyForTheDslAndPrePostButPrePostKeepsTheGrantedAuthorityDefaultsPrefix() {
        ApplicationGraph graph = FixtureScans.scan("factories");
        assertThat(check(graph, "GET /staff/list", "authorizeHttpRequests").requirement().authorities())
                .containsExactly("AUTH_STAFF");
        // 7.1.1's DefaultMethodSecurityExpressionHandler hands each root the factory bean, then, as the
        // GrantedAuthorityDefaults prefix isn't ROLE_, root.setDefaultRolePrefix(GRP_), which sets it on the factory.
        assertThat(check(graph, "GET /pre", "@PreAuthorize").requirement().authorities())
                .containsExactly("GRP_STAFF");
        // hasRole('GRP_STAFF'): SecurityExpressionRoot takes GrantedAuthorityDefaults' GRP_ off first.
        assertThat(check(graph, "GET /pre/prefixed", "@PreAuthorize").requirement().authorities())
                .containsExactly("GRP_STAFF");
    }

    @Test
    void securedAndJsr250KeepTheBeans() {
        ApplicationGraph graph = FixtureScans.scan("factories");
        assertThat(check(graph, "GET /secured", "@Secured").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_STAFF", "ROLE_ADMIN");
        assertThat(check(graph, "GET /jsr250", "@RolesAllowed").requirement().authorities())
                .containsExactly("GRP_STAFF");
    }

    @Test
    void aFactoryPerScope() {
        ApplicationGraph graph = FixtureScans.scan("factoryhttp");
        assertThat(check(graph, "GET /staff/list", "authorizeHttpRequests").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_STAFF", "ROLE_ADMIN");
        assertThat(check(graph, "GET /pre", "@PreAuthorize").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_STAFF", "ROLE_LEAD");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement().asString()
                .contains("requestFactory", "setAdditionalAuthorization");
    }

    private static AuthorizationLocation check(ApplicationGraph graph, String ingress, String mechanism) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals(mechanism)).findFirst().orElseThrow();
    }
}
