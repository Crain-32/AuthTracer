package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class CustomizersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("customizers");

    @Test
    void customizerRulesComeBeforeTheChainsOwn() {
        AuthorizationLocation health = rule(graph, "GET /actuator/health");
        assertThat(health.requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(health.target().method()).isEqualTo("actuator()");
        assertThat(rule(graph, "GET /home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void customizersApplyInOrder() {
        assertThat(rule(graph, "POST /actuator/shutdown").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(rule(graph, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void bootsDefaultChainGetsCustomizerRulesFirst() {
        ApplicationGraph boot = FixtureScans.scan("customizerboot");
        assertThat(rule(boot, "GET /docs/index").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(boot, "GET /data").mechanism()).isEqualTo("Spring Boot default SecurityFilterChain");
    }
}
