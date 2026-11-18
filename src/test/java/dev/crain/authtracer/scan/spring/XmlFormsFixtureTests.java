package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0036: XML chains matched with regular expressions, and a chain with no intercept-url, whose
 * AuthorizationFilter has no rule (7.1.1 AuthorizationFilterParser) and so denies every request.
 */
class XmlFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("xmlforms");

    @Test
    void aRegexChainAndItsRegexRules() {
        AuthorizationLocation report = rule(graph, "GET /legacy/reports/{id}");
        assertThat(report.requirement().authorities()).containsExactly("ROLE_AUDITOR");
        assertThat(report.routePattern()).isEqualTo("regex /legacy/reports/[0-9]+.*");
        assertThat(rule(graph, "GET /legacy/home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(graph, "GET /home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aChainWithoutInterceptUrlsDeniesEveryRequest() {
        AuthorizationLocation hook = rule(graph, "POST /hooks/github");
        assertThat(hook.requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(hook.mechanism()).isEqualTo("intercept-url (no rule matched: denied by default)");
    }
}
