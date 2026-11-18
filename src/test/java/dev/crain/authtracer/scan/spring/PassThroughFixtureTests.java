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
 * Decision 0027 with chains that authorize nothing, or none that covers the request: a chain without
 * authorizeHttpRequests lets its requests through, and so does no chain at all.
 */
class PassThroughFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("passthrough");

    @Test
    void aCoveringChainThatAuthorizesNothingIsTheOpenAlternative() {
        AuthorizationLocation webhook = rule(graph, "POST /webhooks/github");
        assertThat(webhook.id()).startsWith("location:SPLIT:").contains(":or-chains:");
        assertThat(webhook.routePattern()).isEqualTo("anyRequest or no rules");
        assertThat(webhook.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
    }

    @Test
    void aRequestNoChainIsSureToCoverMayStillBeTakenByOne() {
        AuthorizationLocation status = rule(graph, "GET /status");
        assertThat(status.routePattern()).isEqualTo("anyRequest or no chain");
        assertThat(status.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /api/orders").requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
    }

    @Test
    void theInternalChainIsReportedOnce() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .filteredOn(message -> message.contains("PassThroughConfig#internal"))
                .singleElement().satisfies(message -> assertThat(message)
                        .contains("has a securityMatcher AuthTracer can't evaluate (securityMatcher(RequestMatcher))"));
    }
}
