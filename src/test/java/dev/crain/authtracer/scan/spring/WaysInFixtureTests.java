package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.AuthoritySource.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0074: one-time tokens, passkeys, the container's login and remember-me are ways in, which keep the user
 * in the session.
 */
class WaysInFixtureTests {

    @Test
    void magicLinksPasskeysTheContainerAndRememberMeAreWaysIn() {
        AuthoritySource source = FixtureScans.scan("waysin").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.USER_DETAILS);
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
        assertThat(source.detail().split(", (?=[A-Z])")).containsExactlyInAnyOrder("One-time token login (session)",
                "Passkeys (WebAuthn, session)", "Java EE container pre-authentication (session)",
                "Remember-me (session)");
    }

    @Test
    void aRememberMeCookieAloneIsAWayIn() {
        assertThat(FixtureScans.scan("rememberme").authoritySource().detail()).isEqualTo("Remember-me (session)");
    }

    @Test
    void theXmlNamespacesContainerLoginAndRememberMeAreWaysIn() {
        AuthoritySource source = FixtureScans.scan("xmlwaysin").authoritySource();
        assertThat(source.detail()).isEqualTo("Java EE container pre-authentication (session), Remember-me (session)");
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
    }
}
