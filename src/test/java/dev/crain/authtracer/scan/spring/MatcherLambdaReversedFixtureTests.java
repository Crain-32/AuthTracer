package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Lambda matchers that aren't the prefix or exact path tests they look like.
 */
class MatcherLambdaReversedFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("matcherlambdareversed");

    @Test
    void aConstantThatStartsWithThePathMatchesThePathsThatStartIt() {
        assertThat(rule("ingress:GET /admin").requirement().authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void aPathComparedIgnoringCaseMatchesItInAnyCase() {
        assertThat(rule("ingress:GET /ops").requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
    }

    private AuthorizationLocation rule(String ingress) {
        return path(graph, ingress).stream().map(id -> (AuthorizationLocation) graph.node(id).orElseThrow())
                .findFirst().orElseThrow();
    }
}
