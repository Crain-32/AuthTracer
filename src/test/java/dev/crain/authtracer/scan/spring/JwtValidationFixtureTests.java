package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * OAUTH-06 (decision 0073): which tokens a resource server accepts, and where its decoder gets their keys.
 */
class JwtValidationFixtureTests {

    @Test
    void anAudienceClaimValidatorNamesTheAudiencesItAccepts() {
        ApplicationGraph graph = FixtureScans.scan("jwtaudiences");
        AuthoritySource.Jwt jwt = graph.authoritySource().jwt();
        // The second lambda captures the audience from a local.
        assertThat(jwt.audiences()).containsExactly("orders-api", "partner-api");
        assertThat(jwt.validators()).containsExactly("issuer");
        assertThat(jwt.unread()).isEmpty();
        assertThat(graph.authoritySource().detail()).endsWith("; tokens for: orders-api, partner-api");
        // The decoder the application builds finds its keys from the issuer.
        assertThat(graph.nodes(Egress.class)).singleElement().satisfies(egress -> {
            assertThat(egress.client()).isEqualTo("JwtDecoder");
            assertThat(egress.baseUrl()).isEqualTo("https://idp.example.com");
            assertThat(egress.uriTemplate()).isEqualTo("/.well-known/openid-configuration");
        });
    }

    @Test
    void anAccessTokenValidatorAndOneOfTheApplicationsOwn() {
        ApplicationGraph graph = FixtureScans.scan("jwtatvalidator");
        AuthoritySource.Jwt jwt = graph.authoritySource().jwt();
        assertThat(jwt.audiences()).containsExactly("billing-api");
        assertThat(jwt.validators()).containsExactly("issuer", "typ at+jwt");
        assertThat(jwt.unread()).containsExactly("TenantValidator");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).containsExactly("The JWTs the service accepts are also checked by"
                        + " TenantValidator, which the scan doesn't read: whether a token another service relays"
                        + " passes is unknown");
        assertThat(graph.nodes(Egress.class)).singleElement()
                .satisfies(egress -> assertThat(egress.uriTemplate()).isEqualTo("/jwks"));
    }

    @Test
    void bootsDecoderTakesTheAudiencesPropertyAndTheValidatorBeans() {
        AuthoritySource.Jwt jwt = FixtureScans.scan("jwtbootaudiences").authoritySource().jwt();
        assertThat(jwt.audiences()).containsExactly("orders-api", "partner-api");
        assertThat(jwt.validators()).containsExactly("claim tenant", "issuer");
    }

    @Test
    void validatorsBuiltOneByOneAndCombinedFromAList() {
        ApplicationGraph graph = FixtureScans.scan("jwtvalidatorforms");
        AuthoritySource.Jwt jwt = graph.authoritySource().jwt();
        assertThat(jwt.audiences()).containsExactly("orders-api");
        // Both decoders' validators count: the second's access-token validator takes a client id.
        assertThat(jwt.validators()).containsExactly("claim tenant", "client_id", "issuer", "typ", "typ at+jwt");
        assertThat(jwt.unread()).containsExactly("a JwtClaimValidator on aud in JwtValidatorFormsConfig#jwtDecoder",
                "an audience that isn't a constant, in JwtValidatorFormsConfig#jwtDecoder");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).contains("The JWTs the service accepts are also checked by an audience"
                        + " that isn't a constant, in JwtValidatorFormsConfig#jwtDecoder, which the scan doesn't read:"
                        + " whether a token another service relays passes is unknown");
        assertThat(graph.authoritySource().detail()).endsWith("; tokens for: orders-api");
    }
}
