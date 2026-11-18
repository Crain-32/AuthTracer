package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Clauses;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0063 (SRC-11): what callers who haven't signed in hold, and what that does to the checks they meet.
 */
class AnonymousFixtureTests {

    @Test
    void aRoleTheAnonymousAuthenticationCarriesAdmitsAnyone() {
        ApplicationGraph graph = FixtureScans.scan("anonymousauthorities");
        Requirement catalog = rule(graph, "GET /catalog/prices").requirement();
        assertThat(catalog.kind()).isEqualTo(Kind.OR);
        assertThat(catalog.operands().getFirst().kind()).isEqualTo(Kind.ANONYMOUS);
        assertThat(Clauses.of(List.of(catalog))).isEmpty();
        // Method checks see the same token.
        AuthorizationLocation prices = path(graph, "ingress:GET /catalog/prices").stream()
                .map(id -> (AuthorizationLocation) graph.node(id).orElseThrow())
                .filter(location -> location.mechanism().equals("@PreAuthorize")).findFirst().orElseThrow();
        assertThat(prices.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANONYMOUS, Kind.ANY_AUTHORITY);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_GRANTED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("@PreAuthorize", "Catalog#prices",
                        "ROLE_GUEST"))
                .anySatisfy(message -> assertThat(message).contains("authorizeHttpRequests"));
        // A role the token doesn't carry is left as it is.
        assertThat(rule(graph, "GET /orders/mine").requirement().kind()).isEqualTo(Kind.ANY_AUTHORITY);
    }

    @Test
    void withAnonymousAuthenticationOffAnonymousAdmitsNoOne() {
        ApplicationGraph graph = FixtureScans.scan("anonymousoff");
        Requirement signup = rule(graph, "GET /signup").requirement();
        assertThat(signup.kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(signup.expression()).isEqualTo("anonymous");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).singleElement().asString()
                .contains("only callers who haven't signed in", "turned off");
        // Nobody who hasn't signed in holds ROLE_ANONYMOUS then.
        assertThat(rule(graph, "GET /welcome").requirement().kind()).isEqualTo(Kind.ANY_AUTHORITY);
    }

    @Test
    void theDefaultAnonymousRoleIsMetWithoutAFinding() {
        // ROLE_ANONYMOUS is asked for by name: callers who haven't signed in pass, as the check says.
        ApplicationGraph graph = FixtureScans.scan("anonymousdefault");
        Requirement welcome = rule(graph, "GET /welcome").requirement();
        assertThat(welcome.kind()).isEqualTo(Kind.OR);
        assertThat(welcome.operands().getFirst().kind()).isEqualTo(Kind.ANONYMOUS);
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.ALWAYS_GRANTED);
    }

    @Test
    void onWebFluxOnlyAnonymousConfiguredGivesTheRole() {
        ApplicationGraph graph = FixtureScans.scan("anonymousreactive");
        assertThat(rule(graph, "GET /welcome").requirement().kind()).isEqualTo(Kind.ANY_AUTHORITY);
    }
}
