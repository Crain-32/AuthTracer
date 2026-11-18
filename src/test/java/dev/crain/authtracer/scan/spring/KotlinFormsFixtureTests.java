package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-20: the Kotlin DSL's authorize(..) with its matcher defaulted, its other managers, a servlet path of /, and
 * formLogin { } and logout { } with pages of the application's own.
 */
class KotlinFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("kotlinforms");

    @Test
    void aDefaultedMatcherIsAnyRequest() {
        assertThat(rule(graph, "GET /partner/public/terms").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /partner/orders").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(graph, "GET /partner/orders").routePattern()).isEqualTo("anyRequest");
        assertThat(rule(graph, "GET /home").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void theDslsOtherManagers() {
        assertThat(rule(graph, "GET /internal/stats").requirement().expression()).isEqualTo("hasIpAddress(10.0.0.0/8)");
        assertThat(rule(graph, "GET /account/password").requirement().kind()).isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(rule(graph, "GET /audit/log").requirement().authorities()).containsExactly("ROLE_AUDITOR");
    }

    @Test
    void aServletPathOfSlashAddsNothing() {
        assertThat(rule(graph, "GET /root/settings").requirement().authorities()).containsExactly("ROLE_ROOT");
        assertThat(rule(graph, "GET /root/settings").routePattern()).isEqualTo("/root/**");
    }

    @Test
    void theLoginAndLogoutPagesThePropertiesNameAreOpen() {
        // loginPage = "/signin" is setLoginPage("/signin"): permitAll() opens that page, not /login.
        assertThat(rule(graph, "GET /signin").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /bye").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }
}
