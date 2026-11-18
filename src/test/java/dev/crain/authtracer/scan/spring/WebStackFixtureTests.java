package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0079: the web stack is the one Spring Boot picks, and the other stack's security configuration never runs.
 * The fixtures share one classpath with Spring MVC and WebFlux on it.
 */
class WebStackFixtureTests {

    @Test
    void aWebFluxChainInAServletApplicationNeverRunsAndBootsServletChainDoes() {
        ApplicationGraph graph = FixtureScans.scan("webstackservlet");
        assertThat(rule(graph, "GET /admin/reports").mechanism()).isEqualTo("Spring Boot default SecurityFilterChain");
        assertThat(rule(graph, "GET /admin/reports").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .singleElement().satisfies(finding -> {
                    assertThat(finding.message()).startsWith("The SecurityWebFilterChain fixtures.webstackservlet"
                            + ".WebStackServletApplication#chain(").contains("never runs", "Servlet application");
                    assertThat(finding.location().method()).startsWith("chain(");
                });
    }

    @Test
    void theMainMethodChoosesTheReactiveStackAndTheServletChainNeverRuns() {
        ApplicationGraph graph = FixtureScans.scan("webstackcode");
        assertThat(rule(graph, "GET /admin/reports").mechanism()).isEqualTo("authorizeExchange");
        assertThat(rule(graph, "GET /admin/reports").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .singleElement().satisfies(finding -> assertThat(finding.message())
                        .startsWith("The SecurityFilterChain fixtures.webstackcode.WebStackCodeApplication#legacy(")
                        .contains("reactive application"));
    }

    @Test
    void theApplicationBuilderChoosesTheReactiveStack() {
        ApplicationGraph graph = FixtureScans.scan("webstackbuilder");
        assertThat(rule(graph, "GET /reports").mechanism()).isEqualTo("authorizeExchange");
        assertThat(rule(graph, "GET /reports").requirement().authorities()).containsExactly("ROLE_STAFF");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    @Test
    void thePropertyIsBoundAfterTheMainMethodsChoiceAndAnnotationAloneIsReported() {
        ApplicationGraph graph = FixtureScans.scan("webstackproperty");
        assertThat(rule(graph, "GET /reports").mechanism()).isEqualTo("Spring Boot default SecurityFilterChain");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .singleElement().satisfies(finding -> assertThat(finding.message()).startsWith(
                        "@EnableWebFluxSecurity on fixtures.webstackproperty.WebStackPropertyApplication secures"
                                + " nothing"));
    }

    @Test
    void withoutSpringBootTheSecurityConfigurationShowsTheStack() {
        ApplicationGraph graph = FixtureScans.scanWithout("webstacknoboot", "spring-boot");
        assertThat(rule(graph, "GET /reports").mechanism()).isEqualTo("authorizeExchange");
        assertThat(rule(graph, "GET /reports").requirement().authorities()).containsExactly("ROLE_STAFF");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    @Test
    void reactiveFixturesSayTheyAreReactiveAndReportNothing() {
        ApplicationGraph graph = FixtureScans.scan("webflux");
        assertThat(rule(graph, "GET /orders/{id}").mechanism()).isEqualTo("authorizeExchange");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }
}
