package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.AuthoritySource.Kind;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0074: what checks the logins' credentials when it isn't the UserDetailsService. A provider of the
 * application's is shown as unread (SRC-25 also remember-me's services); a JAAS login names its granters (SRC-24).
 */
class AuthenticationProvidersFixtureTests {

    @Test
    void theOneProviderBeanChecksTheFormsPasswordsAndIsntRead() {
        ApplicationGraph graph = FixtureScans.scan("providercomponent");
        assertThat(graph.authoritySource().detail()).isEqualTo("Form login (session), Authenticated by"
                + " LegacyPasswordProvider (not read)");
        // The session keeps what it gave: a snapshot, whatever it reads.
        assertThat(graph.authoritySource().freshness()).isEqualTo(Freshness.SNAPSHOT);
        assertThat(opaque(graph)).containsExactly("The authentication provider LegacyPasswordProvider isn't read:"
                + " AuthTracer can't tell which authorities the logins it checks give, or how fresh they are");
    }

    @Test
    void aChainsOwnProviderMakesBasicsAuthoritiesUnknown() {
        AuthoritySource source = FixtureScans.scan("providerbasic").authoritySource();
        assertThat(source.detail()).isEqualTo("HTTP Basic, Authenticated by ApiKeyProvider (not read)");
        assertThat(source.kind()).isEqualTo(Kind.UNKNOWN);
        assertThat(source.freshness()).isEqualTo(Freshness.UNKNOWN);
    }

    @Test
    void withSeveralProviderBeansTheManagerBeanChecksThePasswords() {
        // Spring's own providers are read as the ways in they serve; the application's one isn't.
        ApplicationGraph graph = FixtureScans.scan("providerbeans");
        assertThat(graph.authoritySource().detail()).isEqualTo("Form login (session), Authenticated by"
                + " TenantProvider (not read)");
    }

    @Test
    void tokensAManagerOfTheApplicationsChecksGrantWhatItSays() {
        AuthoritySource source = FixtureScans.scan("providerlambda").authoritySource();
        assertThat(source.detail()).startsWith("OAuth2 Resource Server (JWT), Authenticated by a lambda in"
                + " ProviderLambdaSecurityConfig#api (not read);");
        // Not only the converter's authorities: no check is judged against them.
        assertThat(source.granted()).isNull();
    }

    @Test
    void rememberMeServicesOfTheApplicationsArentRead() {
        ApplicationGraph graph = FixtureScans.scan("remembermeservices");
        assertThat(graph.authoritySource().detail()).isEqualTo("Form login (session), Remember-me (session),"
                + " Remember-me through SsoCookieServices (not read)");
        assertThat(opaque(graph)).singleElement().asString().startsWith("The RememberMeServices SsoCookieServices");
    }

    @Test
    void aJaasLoginGrantsWhatItsGrantersReturn() {
        ApplicationGraph graph = FixtureScans.scan("jaas");
        assertThat(graph.authoritySource().detail()).isEqualTo("HTTP Basic, JAAS login (authority granters:"
                + " RoleGranter, a lambda in JaasSecurityConfig#jaasProvider, the field auditors (not read))");
        // Basic logs in through JAAS on every request.
        assertThat(graph.authoritySource().freshness()).isEqualTo(Freshness.LIVE);
        assertThat(opaque(graph)).containsExactly("The JAAS AuthorityGranter the field auditors isn't read:"
                + " AuthTracer can't tell which authorities it grants");
    }

    @Test
    void aDirectoryBindChecksTheFormsPasswordsAndGivesTheUsersGroups() {
        // SRC-20: LdapBindAuthenticationManagerFactory's manager, the global one.
        AuthoritySource source = FixtureScans.scan("ldapbind").authoritySource();
        assertThat(source.detail()).isEqualTo("Form login (session), LDAP directory");
        assertThat(source.kind()).isEqualTo(Kind.USER_DETAILS);
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
    }

    @Test
    void basicAgainstADirectoryReadsItOnEveryRequest() {
        // The global builder's ldapAuthentication(), and a chain's Active Directory provider.
        AuthoritySource source = FixtureScans.scan("ldapbuilder").authoritySource();
        assertThat(source.detail()).isEqualTo("HTTP Basic, LDAP directory");
        assertThat(source.freshness()).isEqualTo(Freshness.LIVE);
    }

    @Test
    void aCasFilterIsAWayInThatKeepsTheUserInTheSession() {
        ApplicationGraph graph = FixtureScans.scan("cas");
        assertThat(graph.authoritySource().detail()).isEqualTo("CAS (session)");
        assertThat(graph.authoritySource().kind()).isEqualTo(Kind.IDENTITY_PROVIDER);
        assertThat(graph.authoritySource().freshness()).isEqualTo(Freshness.SNAPSHOT);
        // Its provider is Spring's.
        assertThat(opaque(graph)).isEmpty();
    }

    @Test
    void theKotlinDslSetsTheChainsManagerAsAProperty() {
        assertThat(FixtureScans.scan("providerkotlin").authoritySource().detail()).isEqualTo("HTTP Basic,"
                + " Authenticated by DirectoryProvider (not read)");
    }

    private static java.util.List<String> opaque(ApplicationGraph graph) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .map(Finding::message).toList();
    }
}
