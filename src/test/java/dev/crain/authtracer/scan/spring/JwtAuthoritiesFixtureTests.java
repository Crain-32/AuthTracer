package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.ClaimAuthorities;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0073: which claims a resource server's JWTs turn into which authorities (SRC-02, SRC-03, SRC-04), and the
 * checks no token can pass.
 */
class JwtAuthoritiesFixtureTests {

    @Test
    void aCheckForAScopeTheConverterNoLongerMapsDeniesEveryCaller() {
        ApplicationGraph graph = FixtureScans.scan("jwtauthorities");
        AuthoritySource source = graph.authoritySource();
        assertThat(source.detail())
                .isEqualTo("OAuth2 Resource Server (JWT); authorities: groups (split on \",\") → ROLE_*");
        assertThat(source.jwt().authorities()).containsExactly(
                new ClaimAuthorities(List.of("groups"), null, "ROLE_", ","));
        assertThat(source.granted()).containsExactly("FACTOR_BEARER", "ROLE_*", "ROLE_ANONYMOUS");
        assertThat(alwaysDenied(graph)).containsExactlyInAnyOrder(
                "authorizeHttpRequests on /reports/** asks for SCOPE_reports.read, which no request carries: the"
                        + " service's JWTs grant only FACTOR_BEARER, ROLE_*, ROLE_ANONYMOUS, so it denies every caller",
                "@PreAuthorize on fixtures.jwtauthorities.ExportService#export() asks for SCOPE_exports, which no"
                        + " request carries: the service's JWTs grant only FACTOR_BEARER, ROLE_*, ROLE_ANONYMOUS, so it"
                        + " denies every caller");
        // The check is shown as written.
        assertThat(FixtureScans.rule(graph, "GET /reports/daily").requirement())
                .isEqualTo(Requirement.anyAuthority(List.of("SCOPE_reports.read")).withSource(
                        "hasAuthority(SCOPE_reports.read)"));
    }

    @Test
    void bootsPropertiesSetTheClaimThePrefixAndTheDelimiter() {
        ApplicationGraph graph = FixtureScans.scan("jwtbootauthorities");
        assertThat(graph.authoritySource().detail())
                .isEqualTo("OAuth2 Resource Server (JWT); authorities: roles (split on \";\") → ROLE_*");
        assertThat(alwaysDenied(graph)).singleElement().asString()
                .startsWith("@PreAuthorize on fixtures.jwtbootauthorities.Reports#export() asks for"
                        + " SCOPE_reports.export");
    }

    @Test
    void bootsClaimExpressionsEachGetThePrefix() {
        assertThat(FixtureScans.scan("jwtbootexpressions").authoritySource().jwt().authorities()).containsExactly(
                new ClaimAuthorities(List.of(), "[realm_access][roles]", "ROLE_", null),
                new ClaimAuthorities(List.of(), "[resource_access][orders][roles]", "ROLE_", null));
    }

    @Test
    void anExpressionAndTheDefaultConverterDelegatedTo() {
        ApplicationGraph graph = FixtureScans.scan("jwtexpressions");
        assertThat(graph.authoritySource().detail()).isEqualTo(
                "OAuth2 Resource Server (JWT); authorities: [realm_access][roles] → ROLE_*, scope → SCOPE_*");
        assertThat(alwaysDenied(graph)).singleElement().asString()
                .startsWith("authorizeHttpRequests on /legacy/** asks for GROUP_legacy");
    }

    @Test
    void aConverterOfTheApplicationsOwnIsNotReadSoNoCheckIsCalledAlwaysDenied() {
        ApplicationGraph graph = FixtureScans.scan("jwtcustomconverter");
        assertThat(graph.authoritySource().granted()).isNull();
        assertThat(graph.authoritySource().detail()).isEqualTo("OAuth2 Resource Server (JWT); authorities:"
                + " KeycloakRealmRoleConverter (not read), a lambda in JwtCustomConverterConfig#partners (not read)");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).containsExactlyInAnyOrder(
                        "The JWT authorities come from KeycloakRealmRoleConverter, which the scan doesn't read: which"
                                + " authorities a token grants is unknown, so a check no token can pass isn't told"
                                + " apart",
                        "The JWT authorities come from a lambda in JwtCustomConverterConfig#partners, which the scan"
                                + " doesn't read: which authorities a token grants is unknown, so a check no token can"
                                + " pass isn't told apart");
        assertThat(alwaysDenied(graph)).isEmpty();
    }

    @Test
    void dynamicGroovyIsReadWhereTheCompilerKnowsTheReceiver() {
        ApplicationGraph graph = FixtureScans.scan("jwtgroovy");
        assertThat(graph.authoritySource().detail()).contains("roles → ROLE_*");
        assertThat(graph.authoritySource().granted()).isNull();
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).containsExactlyInAnyOrder(
                        "The JWT authorities come from Groovy code in JwtGroovyConfig#api that configures a converter"
                                + " dynamically, which the scan doesn't read: which authorities a token grants is"
                                + " unknown, so a check no token can pass isn't told apart",
                        "The JWT authorities come from Groovy code in JwtGroovyConfig#converter that configures a"
                                + " converter dynamically, which the scan doesn't read: which authorities a token"
                                + " grants is unknown, so a check no token can pass isn't told apart");
        assertThat(alwaysDenied(graph)).isEmpty();
    }

    @Test
    void aPrincipalConverterAddsTheAuthoritiesItLoadsToTheTokens() {
        AuthoritySource source = FixtureScans.scan("jwtprincipal").authoritySource();
        assertThat(source.detail()).isEqualTo("OAuth2 Resource Server (JWT); authorities: scope → SCOPE_*; plus, per"
                + " request, the authorities of the principal from a lambda in"
                + " JwtPrincipalConfig#jwtAuthenticationConverter");
        // The token's own authorities can't be revoked.
        assertThat(source.freshness()).isEqualTo(AuthoritySource.Freshness.SNAPSHOT);
        assertThat(source.granted()).isNull();
        assertThat(alwaysDenied(FixtureScans.scan("jwtprincipal"))).isEmpty();
    }

    @Test
    void aClaimSetConverterRewritesClaimsBeforeTheyAreRead() {
        ApplicationGraph graph = FixtureScans.scan("jwtclaimset");
        assertThat(graph.authoritySource().jwt().rewritten()).containsExactly("scope");
        assertThat(graph.authoritySource().detail()).endsWith("; claims rewritten first: scope");
        // The prefix still applies to what the rewritten claim holds.
        assertThat(graph.authoritySource().granted()).contains("SCOPE_*");
        assertThat(alwaysDenied(graph)).isEmpty();
    }

    @Test
    void convertersAreFollowedThroughHelpersParametersFieldsAndProviders() {
        ApplicationGraph graph = FixtureScans.scan("jwtforms");
        AuthoritySource source = graph.authoritySource();
        // teams() builds a default converter that configure(..) then changes: both readings count.
        assertThat(source.jwt().authorities()).extracting(JwtSettings::text)
                .containsExactly("regions → ?", "scope → SCOPE_*", "teams → TEAM_*");
        assertThat(source.detail()).endsWith("the field partnerAuthorities (not read); claims rewritten first: teams");
        assertThat(source.granted()).isNull();
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).containsExactlyInAnyOrder(
                        "The JWT authorities come from the field partnerAuthorities, which the scan doesn't read:"
                                + " which authorities a token grants is unknown, so a check no token can pass isn't"
                                + " told apart",
                        "A JwtGrantedAuthoritiesConverter's authority prefix isn't a constant: which authorities a"
                                + " token grants is unknown");
    }

    @Test
    void theReactiveConverterAndItsAdapter() {
        ApplicationGraph graph = FixtureScans.scan("jwtreactive");
        assertThat(graph.authoritySource().jwt().authorities()).extracting(JwtSettings::text)
                .containsExactly("roles → ROLE_*");
        assertThat(graph.authoritySource().jwt().unread()).containsExactly("a lambda in JwtReactiveConfig#jwtDecoder");
        assertThat(alwaysDenied(graph)).singleElement().asString()
                .startsWith("authorizeExchange on /billing/** asks for SCOPE_billing");
    }

    @Test
    void aConverterTheChainMethodIsHandedIsNotReadButTheOneItsBeanBuildsIs() {
        ApplicationGraph graph = FixtureScans.scan("jwtvalidatorforms");
        // The claim name is from the environment; a space is the default delimiter.
        assertThat(graph.authoritySource().jwt().authorities()).containsExactly(
                new ClaimAuthorities(List.of(), null, "ROLE_", null));
        assertThat(graph.authoritySource().detail()).startsWith("OAuth2 Resource Server (JWT); authorities: a claim"
                + " the scan can't read → ROLE_*, an injected Converter (not read);");
        assertThat(graph.findings()).extracting(Finding::message).contains("The JWT authorities come from an"
                + " injected Converter, which the scan doesn't read: which authorities a token grants is unknown, so"
                + " a check no token can pass isn't told apart");
    }

    @Test
    void bootsPrefixFromTheEnvironmentLeavesWhatATokenGrantsUnknown() {
        ApplicationGraph graph = FixtureScans.scan("jwtbootprefix");
        assertThat(graph.authoritySource().detail())
                .isEqualTo("OAuth2 Resource Server (JWT); authorities: groups → ?");
        assertThat(graph.authoritySource().jwt().authorities()).containsExactly(
                new ClaimAuthorities(List.of("groups"), null, null, null));
        // hasRole('LEAD') may be what a token grants.
        assertThat(alwaysDenied(graph)).isEmpty();
    }

    private static List<String> alwaysDenied(ApplicationGraph graph) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .map(Finding::message).toList();
    }
}
