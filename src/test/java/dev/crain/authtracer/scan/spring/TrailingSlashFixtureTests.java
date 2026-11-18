package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Spring Framework 7.0.9's PathPattern#combine keeps a trailing slash, and its PathPatternParser matches it only
 * literally (matchOptionalTrailingSeparator is false): a mapping ending in a slash keeps it in its route.
 */
class TrailingSlashFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("trailingslash");

    @Test
    void aTrailingSlashStaysInTheRoute() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /users/", "ingress:GET /teams/", "ingress:GET /users/{id}",
                        "ingress:GET /teams/{id}")
                .doesNotContain("ingress:GET /users", "ingress:GET /teams");
        assertThat(rule(graph, "GET /users/").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
        assertThat(rule(graph, "GET /teams/").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void theRootAndJoinedPathsHaveNone() {
        assertThat(RequestMappings.routes(List.of(""), List.of("/"))).containsExactly("/");
        assertThat(RequestMappings.routes(List.of("/"), List.of(""))).containsExactly("/");
        assertThat(RequestMappings.routes(List.of("/api/"), List.of("/x"))).containsExactly("/api/x");
        assertThat(RequestMappings.routes(List.of("/api"), List.of("", "x/"))).containsExactly("/api", "/api/x/");
    }
}
