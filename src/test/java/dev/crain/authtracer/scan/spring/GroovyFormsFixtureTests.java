package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Dynamic Groovy passes a Java varargs call's arguments one by one: a method alone, several RequestMatchers, a method
 * and several patterns; a RequestMatcher read from the configuration's field may match any request.
 */
class GroovyFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("groovyforms");

    @Test
    void aMethodAlone() {
        assertThat(rule(graph, "OPTIONS /items").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "OPTIONS /items").routePattern()).isEqualTo("OPTIONS /**");
    }

    @Test
    void severalRequestMatchers() {
        assertThat(rule(graph, "GET /reports/{id}").requirement().authorities()).containsExactly("ROLE_ANALYST");
        assertThat(rule(graph, "GET /exports/latest").requirement().authorities()).containsExactly("ROLE_ANALYST");
        assertThat(rule(graph, "GET /exports/latest").routePattern()).isEqualTo("regex /reports/.*, /exports/**");
    }

    @Test
    void aMethodAndSeveralPatterns() {
        assertThat(rule(graph, "DELETE /orders/{id}").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(graph, "DELETE /orders/{id}").routePattern()).isEqualTo("DELETE /items/**,/orders/**");
    }

    @Test
    void aRequestMatcherFromAFieldMayMatchFirst() {
        AuthorizationLocation home = rule(graph, "GET /home");
        assertThat(home.id()).startsWith("location:SPLIT:");
        assertThat(home.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
    }
}
