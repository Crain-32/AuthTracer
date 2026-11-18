package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A mapping for any method takes every method's requests, so a rule for one method decides only those its caller
 * sends with that method: the other methods get the rules after it (a Split, the weaker reading).
 */
class AnyMethodFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("anymethod");

    @Test
    void aRuleForOneMethodIsOneAlternativeOfAnAnyMethodMapping() {
        AuthorizationLocation summary = rule(graph, "* /reports/summary");
        assertThat(summary.id()).startsWith("location:SPLIT:");
        assertThat(summary.routePattern()).isEqualTo("GET /reports/** or /reports/**");
        assertThat(summary.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
        // The caller's choice of method is known: no finding.
        assertThat(graph.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("/reports/**"));
    }

    @Test
    void aMappingForTheMethodGetsItsRule() {
        assertThat(rule(graph, "GET /reports/detail").requirement().authorities()).containsExactly("ROLE_READER");
    }
}
