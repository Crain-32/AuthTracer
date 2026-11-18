package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0048: {@code @Async} calls leave the caller's SecurityContext behind.
 */
class AsyncFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("async");

    @Test
    void checksOnAnAsyncThreadDenyWhileTheCallersOwnStillApply() {
        List<AuthorizationLocation> checks = checks(graph, "ingress:POST /notify/{user}");
        // The handler's own call to Audit keeps the role; the same check on the @Async thread denies.
        assertThat(checks).filteredOn(check -> check.mechanism().equals("@PreAuthorize")).singleElement()
                .satisfies(check -> assertThat(check.requirement().authorities()).containsExactly("ROLE_AUDITOR"));
        assertThat(checks).filteredOn(check -> check.mechanism().equals("@PreAuthorize (@Async)"))
                .singleElement()
                .satisfies(check -> assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.DENY_ALL));
        // The @Async method's own check runs on its thread too.
        assertThat(checks(graph, "ingress:DELETE /notifications")).extracting(AuthorizationLocation::mechanism)
                .contains("@PreAuthorize (@Async)").doesNotContain("@PreAuthorize");
        // The caller's request has gone on: the work that fails there doesn't deny the endpoint.
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals("ingress:POST /notify/{user}"))
                .first().satisfies(exposure -> assertThat(exposure.requirement()).contains("ROLE_AUDITOR")
                        .doesNotContain("denyAll"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("@Async thread", "Audit#record"));
    }

    @Test
    void asyncChecksOnBranchesDontDenyTheCallerEither() {
        // Either branch hands work to an @Async thread: the endpoint itself needs only its request rule.
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress()
                .equals("ingress:POST /notifications/cleanup")).first()
                .satisfies(exposure -> assertThat(exposure.requirement()).doesNotContain("denyAll"));
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.BYPASSED
                && finding.message().contains("/notifications/cleanup"));
    }

    @Test
    void anAsyncCallHasNoTokenToRelay() {
        assertThat(nodes(graph, "ingress:POST /notify/{user}")).filteredOn(Egress.class::isInstance)
                .map(Egress.class::cast).singleElement()
                .satisfies(egress -> assertThat(egress.credentials()).isEqualTo(Credentials.NONE));
    }

    @Test
    void anExecutorThatCarriesTheContextKeepsTheChecks() {
        ApplicationGraph propagated = FixtureScans.scan("asyncpropagated");
        assertThat(checks(propagated, "ingress:POST /notify/{user}")).extracting(AuthorizationLocation::mechanism)
                .contains("@PreAuthorize").doesNotContain("@PreAuthorize (@Async)");
        assertThat(nodes(propagated, "ingress:POST /notify/{user}")).filteredOn(Egress.class::isInstance)
                .map(Egress.class::cast).singleElement()
                .satisfies(egress -> assertThat(egress.credentials()).isEqualTo(Credentials.RELAY));
    }

    @Test
    void anAsyncClassRunsEachOfItsMethodsOnAnotherThread() {
        assertThat(checks(FixtureScans.scan("asyncforms"), "ingress:POST /mail"))
                .extracting(AuthorizationLocation::mechanism).contains("@PreAuthorize (@Async)")
                .doesNotContain("@PreAuthorize");
    }

    @Test
    void aDelegatingExecutorBeanKeepsTheChecks() {
        assertThat(checks(FixtureScans.scan("asyncdelegating"), "ingress:POST /notify"))
                .extracting(AuthorizationLocation::mechanism).contains("@PreAuthorize")
                .doesNotContain("@PreAuthorize (@Async)");
    }

    private static List<Node> nodes(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow()).toList();
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return nodes(graph, ingress).stream().filter(AuthorizationLocation.class::isInstance)
                .map(AuthorizationLocation.class::cast).toList();
    }
}
