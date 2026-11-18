package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.Arrays;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.AuthoritySource.Kind;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * SRC-08 (decision 0074): a login's authorities are a snapshot when the chain keeps the SecurityContext for the
 * requests after it, and looked up again on each request when it keeps nothing.
 */
class ContextRepositoriesFixtureTests {

    @Test
    void aStatelessChainLooksTheUserUpOnEveryRequestThatSignsIn() {
        AuthoritySource source = FixtureScans.scan("sessionstateless").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.USER_DETAILS);
        assertThat(source.freshness()).isEqualTo(Freshness.LIVE);
        assertThat(source.detail()).isEqualTo("Form login (stateless), HTTP Basic, Remember-me (stateless), One-time"
                + " token login (stateless), Java EE container pre-authentication (stateless)");
    }

    @Test
    void eachChainKeepsTheContextItsOwnWay() {
        AuthoritySource source = FixtureScans.scan("sessionrepositories").authoritySource();
        // Repositories that keep nothing past the request; Basic saving to the session the chain loads; Basic saving
        // to a session a stateless chain never loads.
        assertThat(ways(source)).containsExactlyInAnyOrder("Form login (stateless)", "HTTP Basic (session)",
                "HTTP Basic");
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
    }

    @Test
    void theChainsRepositoryBeanIsReadWhereItIsMade() {
        AuthoritySource source = FixtureScans.scan("sessionbean").authoritySource();
        assertThat(source.detail()).isEqualTo("Form login (stateless)");
        assertThat(source.freshness()).isEqualTo(Freshness.LIVE);
    }

    @Test
    void aRepositoryAuthTracerCantReadIsTakenToKeepTheContext() {
        ApplicationGraph graph = FixtureScans.scan("sessionunread");
        assertThat(graph.authoritySource().detail()).isEqualTo("Form login (session)");
        assertThat(graph.authoritySource().freshness()).isEqualTo(Freshness.SNAPSHOT);
        // The application's own class; one handed to the chain that isn't among the application's beans.
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(finding -> finding.message().substring(0, finding.message().indexOf(" isn't read")),
                        finding -> finding.location().key().replaceAll("\\(.*", ""))
                .containsExactlyInAnyOrder(
                        tuple("The security context repository CookieContextRepository",
                                "fixtures.sessionunread.SessionUnreadSecurityConfig#app"),
                        tuple("The security context repository an injected SecurityContextRepository",
                                "fixtures.sessionunread.SessionUnreadSecurityConfig#admin"));
    }

    @Test
    void aRepositoryIsFollowedThroughHelpersListsAndChoices() {
        ApplicationGraph graph = FixtureScans.scan("sessionforms");
        // A helper's request-only repository; a delegating list with the session's; a field, not read; Basic given
        // the session's repository on one branch.
        assertThat(ways(graph.authoritySource())).containsExactlyInAnyOrder("Form login (stateless)",
                "Form login (session)", "HTTP Basic (session)");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement().asString()
                .startsWith("The security context repository the field shared isn't read");
    }

    @Test
    void theKotlinDslSetsThePolicyAsAProperty() {
        AuthoritySource source = FixtureScans.scan("sessionkotlin").authoritySource();
        assertThat(source.detail()).isEqualTo("Form login (stateless), One-time token login (stateless), Passkeys"
                + " (WebAuthn, stateless)");
        assertThat(source.freshness()).isEqualTo(Freshness.LIVE);
    }

    @Test
    void dynamicGroovyReadsThePolicyAsAStaticProperty() {
        AuthoritySource source = FixtureScans.scan("sessiongroovy").authoritySource();
        assertThat(ways(source)).containsExactlyInAnyOrder("Form login (stateless)", "HTTP Basic (session)");
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
    }

    @Test
    void onWebFluxTheChainsRepositoryIsEveryWayInsUnlessItHasItsOwn() {
        AuthoritySource source = FixtureScans.scan("sessionreactive").authoritySource();
        assertThat(ways(source)).containsExactlyInAnyOrder("Form login (stateless)", "HTTP Basic",
                "One-time token login (stateless)", "HTTP Basic (session)");
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
    }

    private static String[] ways(AuthoritySource source) {
        return Arrays.stream(source.detail().split(", (?=[A-Z])")).toArray(String[]::new);
    }
}
