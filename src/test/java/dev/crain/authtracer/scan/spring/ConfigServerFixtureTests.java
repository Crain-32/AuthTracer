package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0055: Spring Cloud Config Server's endpoints.
 */
class ConfigServerFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("configserver");

    @Test
    void theServersControllersAreIngressUnderItsPrefix() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains(
                // Two handlers of each told apart by what they produce.
                "ingress:GET /config/{name}/{profiles}?produces:application/json",
                "ingress:GET /config/{name}/{profiles}/{label}?produces:application/json",
                "ingress:GET /config/{name}-{profiles}.yml", "ingress:GET /config/{label}/{name}-{profiles}.properties",
                "ingress:POST /config/encrypt", "ingress:POST /config/decrypt", "ingress:GET /config/key");
        assertThat(rule(graph, "GET /config/{name}/{profiles}?produces:application/json").requirement().kind())
                .isEqualTo(Requirement.Kind.AUTHENTICATED);
        assertThat(rule(graph, "POST /config/decrypt").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }

    @Test
    void notWithoutEnableConfigServer() {
        assertThat(FixtureScans.scan("jaxrs").nodes(Ingress.class)).extracting(Ingress::id)
                .noneMatch(id -> id.contains("{profiles}"));
    }
}
