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
 * HTTP-06: a RequestMatcher lambda that compares the request's method, path, URI, headers or parameters with
 * constants is read for what it tests. What a route says about its method and path is known; a header, a parameter
 * and the raw URI are the caller's to decide, so a rule on them may match first (decision 0051), with a BYPASSED
 * finding; anything else keeps the OPAQUE_CONFIG finding.
 */
class MatcherLambdasFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("matcherlambdas");

    @Test
    void aChainMatchedByAPathPrefixLambdaCoversItsPaths() {
        AuthorizationLocation metrics = rule(graph, "GET /internal/metrics");
        assertThat(metrics.requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(metrics.id()).doesNotStartWith("location:SPLIT:");
        assertThat(findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("MatcherLambdasConfig#internal"));
    }

    @Test
    void methodAndPathTestsDecideWithoutASplit() {
        assertThat(rule(graph, "GET /methods/items").id()).doesNotStartWith("location:SPLIT:");
        assertThat(rule(graph, "GET /methods/items").requirement().authorities()).containsExactly("ROLE_READER");
        assertThat(rule(graph, "GET /methods/items").routePattern()).isEqualTo("when GET");
        AuthorizationLocation admin = rule(graph, "DELETE /methods/admin/items/{id}");
        assertThat(admin.requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(admin.routePattern()).isEqualTo("when DELETE and path under /methods/admin");
        assertThat(rule(graph, "DELETE /methods/items/{id}").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void aPreflightMethodReferenceIsReadFromTheLibrary() {
        // CorsUtils.isPreFlightRequest: OPTIONS with the Origin and Access-Control-Request-Method headers.
        AuthorizationLocation preflight = rule(graph, "OPTIONS /methods/items");
        assertThat(preflight.id()).startsWith("location:SPLIT:");
        assertThat(preflight.routePattern()).startsWith("when OPTIONS and header Origin and header"
                + " Access-Control-Request-Method or ");
        assertThat(findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .startsWith("The rule when OPTIONS and header Origin")
                .contains("depends on what the caller sends (the header Origin; the header"
                        + " Access-Control-Request-Method)"));
    }

    @Test
    void aHeaderTheCallerSendsMayTakeTheRequest() {
        AuthorizationLocation report = rule(graph, "GET /headers/report");
        assertThat(report.id()).startsWith("location:SPLIT:");
        assertThat(report.routePattern()).isEqualTo("when header X-Internal or anyRequest");
        assertThat(report.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.PERMIT_ALL, Kind.AUTHENTICATED);
        assertThat(findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .isEqualTo("The rule when header X-Internal (requires permitAll) depends on what the caller"
                                + " sends (the header X-Internal): a caller picks whether its request gets it or the"
                                + " rules after it"));
    }

    @Test
    void aRawUriPrefixCanBeAvoidedByTheCaller() {
        AuthorizationLocation users = rule(graph, "GET /uris/admin/users");
        assertThat(users.id()).startsWith("location:SPLIT:");
        assertThat(users.requirement().operands()).extracting(Requirement::kind)
                .contains(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
        assertThat(findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("The rule when URI under /uris/admin (requires hasRole(ADMIN)) depends on what the"
                                + " caller sends (how it writes the URI"));
    }

    @Test
    void aRawUriPrefixTheRouteDoesntHaveNeverMatches() {
        assertThat(rule(graph, "GET /uris/public").routePattern()).isEqualTo("RequestMatcher or anyRequest");
    }

    @Test
    void aLambdaOnTheCallersAddressStaysUnread() {
        assertThat(findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("The rule RequestMatcher (requires hasRole(NETWORK)) uses a RequestMatcher"
                                + " AuthTracer can't evaluate"));
    }

    @Test
    void aChainMatchedByAHeaderMayTakeRequestsNoOtherChainCovers() {
        AuthorizationLocation status = rule(graph, "GET /status");
        assertThat(status.routePattern()).isEqualTo("anyRequest or no chain");
        assertThat(status.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
        assertThat(findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("The SecurityFilterChain fixtures.matcherlambdas.MatcherLambdasConfig#partners(")
                        .contains("has a securityMatcher (when header X-Partner-Key) that depends on what the caller"
                                + " sends (the header X-Partner-Key)"));
    }

    private List<Finding> findings() {
        return graph.findings();
    }
}
