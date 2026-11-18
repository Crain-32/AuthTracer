package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-04 with several servlets: the DispatcherServlet at /mvc, a servlet of its own at /legacy/* and the H2 console. Request matchers see
 * the path without the context path, so the DispatcherServlet's routes are matched under /mvc and the servlet's on
 * its own path.
 */
class ServletBasePathsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("servletbasepaths");

    @Test
    void aBuilderGivenAnotherBasePathBuildsThatServletsPatterns() {
        // PathPatternRequestMatcher.Builder#basePath replaces the bean's /mvc: the pattern is /legacy/**.
        assertThat(rule(graph, "GET /legacy/**").requirement().authorities()).containsExactly("ROLE_LEGACY");
        assertThat(rule(graph, "GET /legacy/**").routePattern()).isEqualTo("/legacy/**");
    }

    @Test
    void theH2ConsoleIsMatchedOnItsOwnPath() {
        assertThat(rule(graph, "GET /h2-console/**").requirement().authorities()).containsExactly("ROLE_DBA");
    }

    @Test
    void theDispatcherServletsRoutesAreMatchedUnderItsPath() {
        assertThat(rule(graph, "POST /orders/new").requirement().authorities()).containsExactly("ROLE_WRITER");
        assertThat(rule(graph, "POST /orders/new").routePattern()).isEqualTo("POST /mvc/orders/**");
        assertThat(rule(graph, "GET /admin/users").routePattern()).isEqualTo("/mvc/admin/**");
        // Served at /mvc/legacy/report, which the legacy servlet's rule doesn't match.
        assertThat(rule(graph, "GET /legacy/report").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aBasePathFromAPropertyIsReadAndOneAuthTracerCantReadIsReported() {
        ApplicationGraph property = FixtureScans.scan("basepathproperty");
        assertThat(rule(property, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(property, "GET /admin/users").routePattern()).isEqualTo("/mvc/admin/**");
        assertThat(property.findings()).noneMatch(finding -> finding.message().contains("sets a basePath"));
        ApplicationGraph unread = FixtureScans.scan("basepathunread");
        assertThat(rule(unread, "GET /admin/users").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(unread.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("BasePathUnreadApp#mvc(java.lang.String)", "sets a basePath that is neither"));
    }
}
