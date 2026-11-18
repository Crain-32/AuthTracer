package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * RX-15: hand-rolled checks in reactive code, a method together with the lambdas it creates.
 */
class HandRolledReactiveFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("handrolledreactive");

    @Test
    void theReactiveContextReadThroughAMethodReferenceAndAnErrorSignalAreACheck() {
        assertThat(check("ReactiveChecksController#admin")).contains("ReactiveSecurityContextHolder.getContext()",
                "SecurityContext.getAuthentication()", "GrantedAuthority.getAuthority()",
                "Mono.error(AccessDeniedException)");
    }

    @Test
    void theExchangesPrincipalAndAnErrorFromASupplierAreACheck() {
        assertThat(check("ReactiveChecksController#owned")).contains("ServerWebExchange.getPrincipal()",
                "Principal.getName()", "Flux.error(ResponseStatusException)");
    }

    @Test
    void aCredentialHeaderAndTheResponsesStatusAreACheck() {
        assertThat(check("ReactiveChecksController#ping")).contains("HttpHeaders.getFirst(X-Api-Key)",
                "ServerHttpResponse.setStatusCode(UNAUTHORIZED)");
    }

    @Test
    void readingTheCallerWithoutDenyingIsNotACheckAndLambdasAreNotReportedOnTheirOwn() {
        assertThat(checks()).noneMatch(message -> message.contains("#hello") || message.contains("lambda$"));
    }

    private String check(String method) {
        return checks().stream().filter(message -> message.contains(method + "(")).findFirst().orElseThrow();
    }

    private List<String> checks() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .map(Finding::message).toList();
    }
}
