package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0049: Spring Authorization Server's endpoints.
 */
class AuthorizationServerFixtureTests {

    @Test
    void bootConfiguresTheEndpointsWithOidc() {
        ApplicationGraph graph = FixtureScans.scan("authserver");
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /oauth2/authorize",
                "ingress:POST /oauth2/v1/token", "ingress:POST /oauth2/introspect", "ingress:POST /oauth2/revoke",
                "ingress:GET /oauth2/jwks", "ingress:GET /.well-known/oauth-authorization-server",
                "ingress:GET /.well-known/openid-configuration", "ingress:GET /userinfo", "ingress:POST /connect/logout")
                .doesNotContain("ingress:POST /oauth2/token", "ingress:POST /oauth2/device_authorization",
                        "ingress:POST /connect/register");
        // The token endpoint's filter runs after the AuthorizationFilter: the client must be authenticated.
        assertThat(checks(graph, "ingress:POST /oauth2/v1/token")).singleElement().satisfies(check -> {
            assertThat(check.mechanism()).isEqualTo("OAuth2 Authorization Server (authenticated client)");
            assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
        });
        assertThat(checks(graph, "ingress:GET /oauth2/authorize")).singleElement().satisfies(check -> assertThat(
                check.mechanism()).isEqualTo("OAuth2 Authorization Server (signed-in user)"));
        assertThat(checks(graph, "ingress:GET /userinfo")).singleElement().satisfies(check -> assertThat(
                check.requirement().authorities()).containsExactly("SCOPE_openid"));
        // The JWK set and the metadata answer before the AuthorizationFilter: anyone.
        assertThat(checks(graph, "ingress:GET /oauth2/jwks")).singleElement().satisfies(check ->
                assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL));
        // Endpoints that ask the same of their caller share the check.
        assertThat(checks(graph, "ingress:POST /oauth2/revoke")).containsExactlyElementsOf(
                checks(graph, "ingress:POST /oauth2/v1/token"));
    }

    @Test
    void theApplicationsOwnChainWithItsSettings() {
        ApplicationGraph graph = FixtureScans.scan("authservercustom");
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:POST /token",
                "ingress:POST /oauth2/device_authorization", "ingress:GET /oauth2/device_verification",
                "ingress:GET /oauth2/jwks", "ingress:GET /userinfo", "ingress:GET /api/hello");
        assertThat(checks(graph, "ingress:GET /oauth2/device_verification")).singleElement().satisfies(check ->
                assertThat(check.mechanism()).isEqualTo("OAuth2 Authorization Server (signed-in user)"));
        // The application's endpoints still get the second chain's rule: the first is for the endpoints' matcher only.
        assertThat(checks(graph, "ingress:GET /api/hello")).singleElement().satisfies(check -> {
            assertThat(check.mechanism()).isEqualTo("authorizeHttpRequests");
            assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
            assertThat(check.target().method()).startsWith("defaultSecurityFilterChain(");
        });
    }

    @Test
    void bootsJwkSourceServesTheJwkSetOfTheApplicationsChainToo() {
        assertThat(FixtureScans.scan("authserverchain").nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:POST /oauth2/token", "ingress:GET /oauth2/jwks");
    }

    @Test
    void clientsLinkToTheTokenEndpointTheyGetTokensFrom() {
        ApplicationGraph client = FixtureScans.scan("oauthclient");
        assertThat(client.nodes(Egress.class)).singleElement().satisfies(call -> {
            assertThat(call.httpMethod() + " " + call.uriTemplate()).isEqualTo("POST /oauth2/v1/token");
            assertThat(call.credentials()).isEqualTo(Credentials.STATIC);
        });
        SystemGraph system = new Linker().link(List.of(client, FixtureScans.scan("authserver")),
                ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).containsExactly("authserver/ingress:POST /oauth2/v1/token");
        // Getting a token isn't a call made for a caller.
        assertThat(system.findings()).isEmpty();
        // A provider known by its issuer: its OpenID configuration.
        assertThat(FixtureScans.scan("bootlogin").nodes(Egress.class)).extracting(Egress::baseUrl, Egress::uriTemplate)
                .contains(org.assertj.core.groups.Tuple.tuple("https://idp.example.com",
                        "/.well-known/openid-configuration"));
    }

    @Test
    void appliedWithItsConfigurerPushedRequestsAndClientRegistration() {
        ApplicationGraph graph = FixtureScans.scan("authserverwith");
        // Its own AuthorizationServerSettings: the PAR endpoint where they say, and Boot's token-uri property ignored.
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:POST /oauth2/v2/par",
                "ingress:POST /oauth2/register", "ingress:POST /connect/register", "ingress:POST /oauth2/token",
                "ingress:GET /oauth2/jwks").doesNotContain("ingress:POST /ignored/token");
        // Client registration needs a bearer token with client.create; a pushed request, an authenticated client.
        assertThat(checks(graph, "ingress:POST /connect/register")).singleElement().satisfies(check -> assertThat(
                check.requirement().authorities()).containsExactly("SCOPE_client.create"));
        assertThat(checks(graph, "ingress:POST /oauth2/register")).containsExactlyElementsOf(
                checks(graph, "ingress:POST /connect/register"));
        assertThat(checks(graph, "ingress:POST /oauth2/v2/par")).singleElement().satisfies(check -> assertThat(
                check.mechanism()).isEqualTo("OAuth2 Authorization Server (authenticated client)"));
    }

    @Test
    void bootConfiguresItFromClientPropertiesAlone() {
        ApplicationGraph graph = FixtureScans.scan("authserverproperties");
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:POST /oauth2/token",
                "ingress:GET /oidc/me", "ingress:POST /oidc/me").doesNotContain("ingress:GET /userinfo");
    }

    @Test
    void aResourceServersJwkSetIsReadInsteadOfItsIssuersConfiguration() {
        assertThat(FixtureScans.scan("jwkset").nodes(Egress.class))
                .extracting(Egress::client, Egress::httpMethod, Egress::baseUrl, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("JwtDecoder", "GET", "http://idp:9000", "/oauth2/jwks"),
                        tuple("OAuth2 client", "POST", "http://idp:9000", "/oauth2/token"));
        // Without Spring Security's OAuth2 client, the registration's properties get no tokens; without Boot's
        // resource server support, the client still does.
        assertThat(FixtureScans.scanWithout("jwkset", "spring-security-oauth2-client").nodes(Egress.class))
                .extracting(Egress::client).containsExactly("JwtDecoder");
        assertThat(FixtureScans.scanWithout("jwkset", "spring-boot-security-oauth2-resource-server")
                .nodes(Egress.class)).extracting(Egress::client).containsExactly("OAuth2 client");
    }

    @Test
    void opaqueTokensAreIntrospectedWithTheResourceServersOwnCredentials() {
        assertThat(FixtureScans.scan("introspection").nodes(Egress.class)).singleElement().satisfies(call -> {
            assertThat(call.client() + " " + call.httpMethod() + " " + call.baseUrl() + call.uriTemplate())
                    .isEqualTo("OpaqueTokenIntrospector POST http://idp:9000/oauth2/introspect");
            // The client id comes from the environment: set all the same.
            assertThat(call.credentials()).isEqualTo(Credentials.STATIC);
        });
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
