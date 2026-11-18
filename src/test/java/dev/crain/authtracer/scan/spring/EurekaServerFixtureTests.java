package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0057: a Eureka server's endpoints.
 */
class EurekaServerFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("eurekaserver");

    @Test
    void theRegistryAndTheDashboardAreIngress() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /eureka/**",
                "ingress:POST /eureka/**", "ingress:PUT /eureka/**", "ingress:DELETE /eureka/**", "ingress:GET /",
                "ingress:GET /lastn");
        // Anyone can register an instance.
        assertThat(rule(graph, "POST /eureka/**").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void withoutItsDashboardOnlyTheRegistry() {
        assertThat(FixtureScans.scan("eurekaheadless").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /eureka/**").doesNotContain("ingress:GET /", "ingress:GET /lastn");
    }
}
