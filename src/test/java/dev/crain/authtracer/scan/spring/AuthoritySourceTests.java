package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.AuthoritySource.Kind;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Where authorities come from, for the mechanisms spring-security-samples showed unrecognized.
 */
class AuthoritySourceTests {

    @Test
    void anAuthenticationManagerResolverIsEveryManagerItResolvesTo() {
        AuthoritySource source = FixtureScans.scan("multitenant").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.JWT_CLAIMS);
        assertThat(source.detail()).contains("JWT, per AuthenticationManagerResolver")
                .contains("opaque token, per AuthenticationManagerResolver");
        // The JWT tenant's authorities are fixed when its token was issued, so the service's are not all live.
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
    }

    @Test
    void aClientCertificateIsLookedUpOnEveryRequest() {
        AuthoritySource source = FixtureScans.scan("x509").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.USER_DETAILS);
        assertThat(source.detail()).isEqualTo("X.509 client certificate");
        assertThat(source.freshness()).isEqualTo(Freshness.LIVE);
    }

    @Test
    void bootsResourceServerChainReplacesTheDefaultWhenAnIssuerIsConfigured() {
        ApplicationGraph graph = FixtureScans.scan("bootjwt");
        assertThat(graph.authoritySource().kind()).isEqualTo(Kind.JWT_CLAIMS);
        // Boot's converter reads the claim the properties name, with its default prefix.
        assertThat(graph.authoritySource().detail())
                .isEqualTo("OAuth2 Resource Server (JWT); authorities: roles → SCOPE_*");
        assertThat(FixtureScans.rule(graph, "GET /reports").requirement()).isEqualTo(Requirement.authenticated());
    }

    @Test
    void bootsResourceServerChainIntrospectsWhenAnIntrospectionEndpointIsConfigured() {
        AuthoritySource source = FixtureScans.scan("bootopaque").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.OPAQUE_TOKEN_INTROSPECTION);
        assertThat(source.detail()).isEqualTo("OAuth2 Resource Server (opaque token)");
        assertThat(source.freshness()).isEqualTo(Freshness.LIVE);
    }

    @Test
    void bootsOpaqueTokenChainTakesAnyIntrospectorBean() {
        // A RestClientOpaqueTokenIntrospector (new in 7.1) is an OpaqueTokenIntrospector, which Boot's chain asks for.
        ApplicationGraph graph = FixtureScans.scan("bootintrospectorbean");
        assertThat(graph.authoritySource().kind()).isEqualTo(Kind.OPAQUE_TOKEN_INTROSPECTION);
        assertThat(graph.authoritySource().freshness()).isEqualTo(Freshness.LIVE);
        assertThat(FixtureScans.rule(graph, "GET /reports").requirement()).isEqualTo(Requirement.authenticated());
    }

    @Test
    void bootsJwtChainTakesADecoderBeanOfTheApplicationsOwnClass() {
        AuthoritySource source = FixtureScans.scan("bootdecoderbean").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.JWT_CLAIMS);
        assertThat(source.detail()).startsWith("OAuth2 Resource Server (JWT)");
    }

    @Test
    void aChainOfTheOtherWebStackNeverRuns() {
        // A Servlet application: its WebFlux chain's JWTs are no way in, and Boot's default chain is.
        AuthoritySource source = FixtureScans.scan("webstackchains").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.USER_DETAILS);
        assertThat(source.detail()).isEqualTo("Form login (session), HTTP Basic");
    }

    @Test
    void aConverterGivenAClaimNameReadsThatClaimOnly() {
        assertThat(FixtureScans.scan("jwtclaims").authoritySource().detail())
                .isEqualTo("OAuth2 Resource Server (JWT); authorities: roles → ROLE_*");
        // A second converter, left to its default, reads scope.
        assertThat(FixtureScans.scan("jwtclaimsmixed").authoritySource().detail())
                .isEqualTo("OAuth2 Resource Server (JWT); authorities: roles → ROLE_*, scope → SCOPE_*");
    }

    @Test
    void bootsOAuth2LoginChainReplacesTheDefaultWhenAClientIsRegistered() {
        ApplicationGraph graph = FixtureScans.scan("bootlogin");
        assertThat(graph.authoritySource().kind()).isEqualTo(Kind.IDENTITY_PROVIDER);
        assertThat(graph.authoritySource().detail()).isEqualTo("OAuth2 Login (session)");
        assertThat(graph.authoritySource().freshness()).isEqualTo(Freshness.SNAPSHOT);
        assertThat(FixtureScans.rule(graph, "GET /profile").requirement()).isEqualTo(Requirement.authenticated());
    }
}
