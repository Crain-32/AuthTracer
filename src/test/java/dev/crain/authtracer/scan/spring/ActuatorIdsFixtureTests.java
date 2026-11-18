package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Spring Boot 4.1.1 compares endpoint ids as EndpointId does (IncludeExcludeEndpointFilter, MappingWebEndpointPathMapper),
 * and serves the health endpoint at its groups' additional paths (WebMvcHealthEndpointExtensionAutoConfiguration), which
 * ManagementWebSecurityAutoConfiguration permits with the health endpoint.
 */
class ActuatorIdsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("actuatorids");

    @Test
    void idsAreComparedAsBootComparesThem() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /actuator/health", "ingress:GET /actuator/configprops",
                        "ingress:GET /actuator/threads")
                .doesNotContain("ingress:GET /actuator/scheduledtasks", "ingress:GET /actuator/threaddump");
        assertThat(rule(graph, "GET /actuator/threads").requirement().kind())
                .isEqualTo(Requirement.Kind.AUTHENTICATED);
        assertThat(ActuatorEndpoints.canonicalId("HTTP-Exchanges")).isEqualTo("httpexchanges");
    }

    @Test
    void healthGroupsAndProbesServeAtTheirAdditionalPaths() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /healthz", "ingress:GET /livez", "ingress:GET /readyz");
        assertThat(((Ingress) graph.node("ingress:GET /healthz").orElseThrow()).handler().method())
                .isEqualTo(((Ingress) graph.node("ingress:GET /actuator/health").orElseThrow()).handler().method());
        assertThat(rule(graph, "GET /healthz").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /livez").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /hello").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }
}
