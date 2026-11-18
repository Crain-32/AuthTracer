package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

import java.util.Set;

import dev.crain.authtracer.graph.Issuer;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * SRC-19 (decision 0075): the clients an authorization server registers, and the scopes each can be granted.
 */
class RegisteredClientsFixtureTests {

    @Test
    void eachClientsScopesAreReadFromItsBuilder() {
        Issuer issuer = FixtureScans.scan("authserverclients").issuer();
        // Chained, set one call at a time, and added by a consumer.
        assertThat(issuer.clients()).containsOnly(entry("web", sorted("openid", "orders.read")),
                entry("batch", sorted("orders.export", "orders.read")));
        assertThat(issuer.scopes()).containsExactly("openid", "orders.export", "orders.read");
        assertThat(issuer.claims()).containsExactly("department");
        assertThat(issuer.unread()).isEmpty();
    }

    @Test
    void bootsClientsComeFromItsProperties() {
        Issuer issuer = FixtureScans.scan("authserverproperties").issuer();
        assertThat(issuer.clients()).containsOnly(entry("web", sorted("openid")));
        assertThat(issuer.unread()).isEmpty();
    }

    @Test
    void whatMayGiveATokenOtherScopesIsUnread() {
        Issuer issuer = FixtureScans.scan("authserverunread").issuer();
        assertThat(issuer.unread()).containsExactlyInAnyOrder("the clients TenantClients stores",
                "the scopes of a client AuthServerUnreadApp#registeredClientRepository builds",
                "the claims a token customizer in AuthServerUnreadApp#support writes");
        assertThat(issuer.claims()).containsExactly("scope");
    }

    @Test
    void whatTheServerDoesBeyondItsRegistrationsIsUnread() {
        Issuer issuer = FixtureScans.scan("authserverextensions").issuer();
        // Only the client whose scopes a consumer adds as constants is read in full.
        assertThat(issuer.clients()).containsOnly(entry("web", sorted("openid", "orders.read")),
                entry("mobile", sorted()), entry("a client AuthServerExtensionsApp#clients builds", sorted()),
                entry("trimmed", sorted()), entry("partner", sorted()), entry("kiosk", sorted()));
        String chain = "AuthServerExtensionsApp#authorizationServer";
        assertThat(issuer.unread()).containsExactlyInAnyOrder(
                "the clients AuthServerExtensionsApp#registeredClientRepository returns",
                "the scopes of a client AuthServerExtensionsApp#clients builds",
                "the tokens ScopedTokens generates",
                "the tokens a token generator set in " + chain + " issues",
                "the tokens the token endpoint's own providers in " + chain + " issue",
                "the scopes an authentication validator set in " + chain + " allows",
                "the clients registered at run time (client registration endpoint in " + chain + ")",
                "the claims a token customizer in AuthServerExtensionsApp#tenant writes",
                "the claims a token customizer in AuthServerExtensionsApp#extras writes");
        assertThat(issuer.claims()).isEmpty();
    }

    @Test
    void aServiceThatIssuesNoTokensHasNoIssuer() {
        assertThat(FixtureScans.scan("jwtclaims").issuer()).isNull();
    }

    private static java.util.SortedSet<String> sorted(String... scopes) {
        return new java.util.TreeSet<>(Set.of(scopes));
    }
}
