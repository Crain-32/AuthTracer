package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * OAUTH-07: a servlet resource server's protected resource metadata.
 */
class ResourceServerMetadataFixtureTests {

    private static final String METADATA = "ingress:GET /.well-known/oauth-protected-resource/**";

    @Test
    void aResourceServerChainAnswersItsMetadataToAnyoneBeforeItsRule() {
        ApplicationGraph graph = FixtureScans.scan("resourcemetadata");
        assertThat(((Ingress) graph.node(METADATA).orElseThrow()).handler().className())
                .isEqualTo("org.springframework.security.oauth2.server.resource.web."
                        + "OAuth2ProtectedResourceMetadataFilter");
        AuthorizationLocation check = FixtureScans.rule(graph, "GET /.well-known/oauth-protected-resource/**");
        assertThat(check.mechanism()).isEqualTo("OAuth2 Resource Server (public: answers before authorization)");
        assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }

    @Test
    void inEveryDslAndBootsOwnChain() {
        assertThat(FixtureScans.scan("kotlindsl").node(METADATA)).isPresent();
        assertThat(FixtureScans.scan("jwtgroovy").node(METADATA)).isPresent();
        assertThat(FixtureScans.scan("jwkset").node(METADATA)).isPresent();
        // A helper the chain calls: it may be any chain's.
        assertThat(FixtureScans.scan("resourcemetadatahelper").node(METADATA)).isPresent();
    }

    @Test
    void notWhereNoResourceServerChainTakesThePath() {
        // Its chain takes /api/** only; another chain takes the metadata path.
        assertThat(FixtureScans.scan("resourcemetadatamatcher").node(METADATA)).isEmpty();
        // Boot's authorization server chains replace its resource server one, and take only their endpoints.
        assertThat(FixtureScans.scan("authserverproperties").node(METADATA)).isEmpty();
        // WebFlux's resource server adds no metadata filter.
        assertThat(FixtureScans.scan("jwtreactive").node(METADATA)).isEmpty();
    }

    @Test
    void withClientRegistrationsTooWhichOfBootsChainsIsMadeIsAFinding() {
        // Boot 4.1.1 makes its resource server chain or its OAuth2 client one, whichever auto-configuration's jar
        // comes first on the classpath: the booted fixture gets OAuth2 Login's, so the metadata asks for a login.
        assertThat(FixtureScans.scan("jwkset").findings())
                .filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG).extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("resource server chain", "OAuth2 Login chain",
                        "classpath", "/.well-known/oauth-protected-resource"));
        assertThat(FixtureScans.scanWithout("jwkset", "spring-security-oauth2-client").findings())
                .noneMatch(finding -> finding.message().contains("OAuth2 Login chain"));
    }
}
