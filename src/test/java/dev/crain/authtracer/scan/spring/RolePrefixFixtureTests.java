package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.SortedSet;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class RolePrefixFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("prefix");

    @Test
    void theDslAndPrePostAndJsr250UseTheConfiguredPrefix() {
        assertThat(authorities("GET /dsl", true)).containsExactly("PERM_ADMIN");
        assertThat(authorities("GET /pre", false)).containsExactly("PERM_USER");
        assertThat(authorities("GET /jsr250", false)).containsExactly("PERM_AUDITOR");
    }

    @Test
    void managersBuiltOutsideTheDslKeepRolePrefix() {
        assertThat(authorities("GET /factory", true)).containsExactly("ROLE_OPS");
        assertThat(authorities("GET /expression", true)).containsExactly("ROLE_LEGACY");
    }

    @Test
    void securedTakesFullAuthorityNames() {
        assertThat(authorities("GET /secured", false)).containsExactly("ROLE_STAFF");
    }

    private SortedSet<String> authorities(String ingress, boolean first) {
        var path = path(graph, "ingress:" + ingress);
        String id = first ? path.getFirst() : path.getLast();
        return ((AuthorizationLocation) graph.node(id).orElseThrow()).requirement().authorities();
    }
}
