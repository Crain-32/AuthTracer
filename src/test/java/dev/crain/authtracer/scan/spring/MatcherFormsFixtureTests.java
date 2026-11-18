package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-06: RequestMatcher lambdas in more of the shapes configurations write, each read for what it tests.
 */
class MatcherFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("matcherforms");

    @Test
    void aMissingParameterIsTheCallersChoice() {
        AuthorizationLocation report = rule(graph, "GET /params/report");
        assertThat(report.routePattern()).isEqualTo("when no parameter debug or anyRequest");
        assertThat(report.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
        assertThat(bypassed()).anySatisfy(message -> assertThat(message)
                .startsWith("The rule when no parameter debug (requires hasRole(USER)) depends on what the caller"
                        + " sends (the parameter debug)"));
    }

    @Test
    void anExactPathAndANegatedPrefixDecideByTheRoute() {
        assertThat(authorities("GET /paths/exact")).containsExactly("ROLE_EXACT");
        assertThat(rule(graph, "GET /paths/exact").routePattern()).isEqualTo("when path /paths/exact");
        assertThat(authorities("GET /paths/exact/{id}")).containsExactly("ROLE_OTHER");
        assertThat(authorities("GET /paths/other")).containsExactly("ROLE_OTHER");
        assertThat(rule(graph, "GET /paths/other").routePattern()).isEqualTo("when path not under /paths/api");
    }

    @Test
    void helperPredicatesAndMethodReferencesToThemAreRead() {
        assertThat(authorities("GET /paths/api/admin/users")).containsExactly("ROLE_ADMIN");
        assertThat(authorities("GET /paths/api/tenants/{tenant}")).containsExactly("ROLE_TENANT");
    }

    @Test
    void aPathVariableBeforeThePrefixEndsLetsThePathDecide() {
        AuthorizationLocation area = rule(graph, "GET /paths/api/{area}/users");
        assertThat(area.id()).startsWith("location:SPLIT:");
        assertThat(area.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
        // What the route's path is, is known: no finding.
        assertThat(graph.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("/paths/api/admin"));
    }

    @Test
    void aMethodComparedWithoutCaseMatchesItsRequests() {
        assertThat(authorities("PATCH /verbs/item")).containsExactly("ROLE_EDITOR");
        assertThat(rule(graph, "PATCH /verbs/item").routePattern()).isEqualTo("when PATCH");
        assertThat(authorities("GET /verbs/item")).containsExactly("ROLE_READER");
        assertThat(rule(graph, "GET /verbs/item").routePattern()).isEqualTo("when GET or HEAD");
        // A mapping for any method: the caller picks one.
        assertThat(rule(graph, "* /verbs/any").requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
    }

    @Test
    void aWholeRawUriAndAHeaderTestedByAUtilityAreTheCallersChoice() {
        assertThat(rule(graph, "GET /raw/report").requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL, Kind.AUTHENTICATED);
        assertThat(bypassed())
                .anySatisfy(message -> assertThat(message).startsWith("The rule when URI /raw/report"))
                .anySatisfy(message -> assertThat(message).startsWith("The rule when header X-Trace"));
    }

    @Test
    void aTestAuthTracerDoesntReadLeavesTheMatcherUnread() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("The rule RequestMatcher (requires permitAll) uses a RequestMatcher AuthTracer"
                                + " can't evaluate"));
    }

    private List<String> authorities(String ingress) {
        return List.copyOf(rule(graph, ingress).requirement().authorities());
    }

    private List<String> bypassed() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .map(Finding::message).toList();
    }
}
