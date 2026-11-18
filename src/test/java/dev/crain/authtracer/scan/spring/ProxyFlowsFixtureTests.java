package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0014: a field check counts wherever the proxy travels before its getter is called.
 */
class ProxyFlowsFixtureTests {

    private static final String IBAN = "location:FIELD:fixtures.proxyflows.Account#getIban():@PreAuthorize";

    private final ApplicationGraph graph = FixtureScans.scan("proxyflows");

    @Test
    void aProxyPassedToAnotherBeanIsStillAProxyThere() {
        assertThat(path(graph, "ingress:GET /accounts/passed")).containsExactly(IBAN);
        assertThat(path(graph, "ingress:GET /accounts/bound")).containsExactly(IBAN);
    }

    @Test
    void aLambdaThatCapturesAProxyReadsThroughIt() {
        assertThat(path(graph, "ingress:GET /accounts/captured")).containsExactly(IBAN);
    }

    @Test
    void anIsGetterIsAFieldCheckToo() {
        assertThat(path(graph, "ingress:GET /accounts/frozen"))
                .containsExactly("location:FIELD:fixtures.proxyflows.Account#isFrozen():@PreAuthorize");
        assertThat(((AuthorizationLocation) graph.node(path(graph, "ingress:GET /accounts/frozen").getFirst())
                .orElseThrow()).field()).isEqualTo("frozen");
    }

    @Test
    void aRepositoryMethodThatAuthorizesItsResultReturnsAProxy() {
        assertThat(path(graph, "ingress:GET /accounts/by-iban")).containsExactly(IBAN);
    }

    @Test
    void theProxyFactorysElementTypeIsFollowedThroughACast() {
        assertThat(path(graph, "ingress:GET /cards"))
                .containsExactly("location:FIELD:fixtures.proxyflows.Card#getNumber():@PreAuthorize");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    @Test
    void anElementOfAProxiedArrayOrOptionalIsAProxy() {
        assertThat(path(graph, "ingress:GET /accounts/array")).containsExactly(IBAN);
        assertThat(path(graph, "ingress:GET /accounts/optional")).containsExactly(IBAN);
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.BYPASSED);
    }
}
