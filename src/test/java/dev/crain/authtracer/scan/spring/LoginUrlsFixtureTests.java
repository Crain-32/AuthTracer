package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-18: formLogin(..).permitAll() and logout(..).permitAll() let everyone reach the URLs they configure, ahead of
 * every rule (7.1.1 PermitAllSupport).
 */
class LoginUrlsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("loginurls");

    @Test
    void theLoginPageAndItsFailurePageAreOpen() {
        assertThat(rule(graph, "GET /account/login").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        // The failure URL is permitted too (AbstractAuthenticationFilterConfigurer#updateAccessDefaults).
        assertThat(rule(graph, "GET /account/login-failed").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /account/login").routePattern())
                .isEqualTo("/account/login,/account/authenticate,/account/login-failed");
    }

    @Test
    void theLogoutUrlsAreOpen() {
        assertThat(rule(graph, "GET /account/goodbye").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        // Decision 0093: with CSRF protection on, the logout URL is POST's only.
        assertThat(rule(graph, "GET /account/goodbye").routePattern())
                .isEqualTo("POST /account/logout, /account/goodbye");
        // Its success URL is the default login page's, /login?logout, and the logout URL takes no GET.
        assertThat(rule(graph, "GET /partner/logout").requirement().authorities()).containsExactly("ROLE_PARTNER");
    }

    @Test
    void everythingElseFollowsTheRules() {
        assertThat(rule(graph, "GET /account/settings").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        // formLogin(withDefaults()) without permitAll() permits nothing.
        assertThat(rule(graph, "GET /partner/home").requirement().authorities()).containsExactly("ROLE_PARTNER");
    }
}
