package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class TemplatesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("templates");

    @Test
    void placeholdersTakeTheCarriersValue() {
        Requirement admin = requirement("GET /admin");
        assertThat(admin.authorities()).containsExactly("ROLE_ADMIN");
        assertThat(admin.expression()).isEqualTo("hasRole('ADMIN')");
    }

    @Test
    void arraysAreJoined() {
        assertThat(requirement("GET /reports").authorities())
                .containsExactly("SCOPE_reports.admin", "SCOPE_reports.read");
    }

    @Test
    void defaultsApplyWhenTheAttributeIsOmitted() {
        assertThat(requirement("GET /tenant").authorities()).containsExactly("tenant:acme");
        assertThat(requirement("GET /other-tenant").authorities()).containsExactly("tenant:globex");
    }

    private Requirement requirement(String ingress) {
        return ((AuthorizationLocation) graph.node(path(graph, "ingress:" + ingress).getLast()).orElseThrow())
                .requirement();
    }
}
