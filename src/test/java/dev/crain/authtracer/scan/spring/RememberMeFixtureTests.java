package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class RememberMeFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("rememberme");

    @Test
    void fullyAuthenticatedKeepsRememberMeSessionsOut() {
        assertThat(rule(graph, "POST /account/password").requirement().kind())
                .isEqualTo(Requirement.Kind.FULLY_AUTHENTICATED);
        assertThat(path(graph, "ingress:GET /account/email")).last().satisfies(id -> assertThat(
                ((AuthorizationLocation) graph.node(id).orElseThrow()).requirement().kind())
                .isEqualTo(Requirement.Kind.FULLY_AUTHENTICATED));
    }

    @Test
    void rememberMeAdmitsRememberMeSessionsOnly() {
        assertThat(rule(graph, "GET /welcome-back").requirement().kind()).isEqualTo(Requirement.Kind.REMEMBER_ME);
        assertThat(rule(graph, "GET /account/email").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }
}
