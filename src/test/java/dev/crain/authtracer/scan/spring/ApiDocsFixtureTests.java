package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0054: springdoc-openapi's endpoints.
 */
class ApiDocsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("apidocs");

    @Test
    void theApiDocsAndTheUiAreIngressCheckedByTheRequestRules() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /api-docs",
                "ingress:GET /api-docs.yaml", "ingress:GET /api-docs/swagger-config", "ingress:GET /swagger-ui.html",
                "ingress:GET /swagger-ui/**");
        assertThat(rule(graph, "GET /swagger-ui/**").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /api-docs").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void onlyWhereSpringBootConfiguresIt() {
        // springdoc is on every fixture's classpath: a Boot application gets its default path, one without Boot's
        // auto-configuration and a WebFlux one none.
        assertThat(FixtureScans.scan("jaxrs").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /v3/api-docs");
        assertThat(FixtureScans.scan("websocket").nodes(Ingress.class)).extracting(Ingress::id)
                .noneMatch(id -> id.contains("api-docs"));
        assertThat(FixtureScans.scan("rsocketdefault").nodes(Ingress.class)).extracting(Ingress::id)
                .noneMatch(id -> id.contains("api-docs"));
    }

    @Test
    void theUiAndTheDocsCanBeTurnedOff() {
        assertThat(FixtureScans.scan("apidocsnoui").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /v3/api-docs", "ingress:GET /v3/api-docs.yaml")
                .noneMatch(id -> id.contains("swagger"));
        assertThat(FixtureScans.scan("apidocsoff").nodes(Ingress.class)).extracting(Ingress::id)
                .noneMatch(id -> id.contains("api-docs") || id.contains("swagger"));
    }
}
