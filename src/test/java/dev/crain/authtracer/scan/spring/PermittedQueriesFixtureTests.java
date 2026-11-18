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
 * Decision 0093: the login and logout URLs permitAll() lets through are compared with the request's URI and query
 * string exactly (7.1.1 PermitAllSupport$ExactUrlRequestMatcher), and the logout URL is LogoutConfigurer's own
 * matcher, POST's only while CSRF protection is on. MultiFactor method references and a factory's trust resolver
 * are read too.
 */
class PermittedQueriesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("permittedqueries");

    @Test
    void aUrlWithAQueryStringOpensTheRouteOnlyToThoseWhoSendIt() {
        AuthorizationLocation home = rule(graph, "GET /partner/home");
        assertThat(home.id()).startsWith("location:SPLIT:");
        assertThat(home.requirement().kind()).isEqualTo(Kind.OR);
        assertThat(home.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.PERMIT_ALL, Kind.ANY_AUTHORITY);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("/partner/home?bye",
                        "the query string ?bye on /partner/home"))
                // The members' logout success URL is their login page's ?logout.
                .anySatisfy(message -> assertThat(message).contains("the query string ?logout on /members/signin"));
        assertThat(rule(graph, "GET /members/signin").id()).startsWith("location:SPLIT:");
    }

    @Test
    void theLogoutUrlTakesEveryMethodOnlyWithoutCsrfProtection() {
        // csrf(AbstractHttpConfigurer::disable) and csrf(csrf -> csrf.disable()).
        assertThat(rule(graph, "GET /partner/logout").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /staff/logout").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /members/logout").requirement().authorities()).containsExactly("ROLE_MEMBER");
    }

    @Test
    void handlersPermitNoUrl() {
        assertThat(rule(graph, "GET /staff/signin").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /guests/oops").requirement().authorities()).containsExactly("ROLE_GUEST");
        assertThat(rule(graph, "GET /staff/logout").routePattern()).doesNotContain("?");
        // A failure URL set after a failure handler is permitted again.
        assertThat(rule(graph, "GET /staff/oops").id()).startsWith("location:SPLIT:");
        assertThat(graph.findings()).extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("the query string ?bad on /staff/oops"));
    }

    @Test
    void aLogoutRequestMatcherReplacesTheLogoutUrl() {
        assertThat(rule(graph, "GET /guests/bye").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /guests/bye").routePattern()).isEqualTo("GET /guests/bye, /login?logout");
    }

    @Test
    void methodReferencesToTheFactorShorthandsAskForTheirFactors() {
        ApplicationGraph references = FixtureScans.scan("mfareferences");
        Requirement home = rule(references, "GET /home").requirement();
        assertThat(home.operands().getLast().authorities()).containsExactly("FACTOR_PASSWORD");
        assertThat(rule(references, "GET /keys/rotate").requirement().authorities())
                .containsExactly("FACTOR_WEBAUTHN");
        // AUTHZ-06: the factory's own trust resolver.
        assertThat(references.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("authorizationManagerFactory()", "AuthenticationTrustResolver"));
    }
}
