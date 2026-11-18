package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthoritySource.Freshness;
import dev.crain.authtracer.graph.AuthoritySource.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0071: a filter that sets the Authentication itself is a way in, with the authorities it sets.
 */
class FilterAuthenticationFixtureTests {

    @Test
    void aFilterThatDecodesATokenItselfGivesSnapshotAuthorities() {
        AuthoritySource source = FixtureScans.scan("filterauth").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.CUSTOM_FILTER);
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
        assertThat(source.detail()).isEqualTo("Custom filter JwtFilter (UsernamePasswordAuthenticationToken;"
                + " authorities ROLE_USER, ROLE_READER; decodes a token: JwtDecoder#decode), Custom filter"
                + " PasswordHeaderFilter (UsernamePasswordAuthenticationToken; authenticates with"
                + " AuthenticationManager#authenticate)");
    }

    @Test
    void aFilterThatLooksTheCallerUpOnEveryRequestGivesLiveAuthorities() {
        AuthoritySource source = FixtureScans.scan("filterauthlive").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.CUSTOM_FILTER);
        assertThat(source.freshness()).isEqualTo(Freshness.LIVE);
        assertThat(source.detail()).isEqualTo("Custom filter ApiKeyFilter (PreAuthenticatedAuthenticationToken;"
                + " looks the caller up on every request: ApiKeys#findById)");
    }

    @Test
    void aFilterBesideBootsDefaultChainIsAWayInToo() {
        AuthoritySource source = FixtureScans.scan("filterauthboot").authoritySource();
        // Boot registers the component at the lowest precedence, after Spring Security's filter and its rule.
        assertThat(source.detail()).isEqualTo("Form login (session), HTTP Basic, Custom filter ProxyHeaderFilter"
                + " (after the AuthorizationFilter; PreAuthenticatedAuthenticationToken; authorities ROLE_STAFF; from"
                + " what the request carries)");
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
    }

    @Test
    void aWebFilterThatWritesAnAuthenticationIntoTheContextIsAWayIn() {
        AuthoritySource source = FixtureScans.scan("webfilterauth").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.CUSTOM_FILTER);
        assertThat(source.detail()).isEqualTo("Custom filter ServiceWebFilter (UsernamePasswordAuthenticationToken;"
                + " authorities ROLE_SERVICE, ROLE_INTERNAL; from what the request carries)");
    }

    @Test
    void aSubclassOfALoginFilterAuthenticatesTheRequestsItsMatcherTakes() {
        AuthoritySource source = FixtureScans.scan("filterforms").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.CUSTOM_FILTER);
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
        assertThat(source.detail()).isEqualTo("Custom filter LoginFilter (extends"
                + " AbstractAuthenticationProcessingFilter; looks the caller up when it authenticates: RestClient#get)");
    }

    @Test
    void aSubclassOfAPreAuthenticationFilterKeepsWhatItSetsInTheSessionALoginFilterDoesntSayWhere() {
        AuthoritySource source = FixtureScans.scan("filterauthpreauth").authoritySource();
        assertThat(source.kind()).isEqualTo(Kind.CUSTOM_FILTER);
        assertThat(source.freshness()).isEqualTo(Freshness.SNAPSHOT);
        assertThat(source.detail()).isEqualTo("Custom filter GatewayHeaderFilter (extends"
                + " AbstractPreAuthenticatedProcessingFilter; kept in the session), Custom filter KioskLoginFilter"
                + " (extends AbstractAuthenticationProcessingFilter; UsernamePasswordAuthenticationToken; authorities"
                + " ROLE_KIOSK; authenticates what attemptAuthentication returns)");
    }

    @Test
    void aFilterThatOnlyReadsTheCallerAddsNoWayIn() {
        assertThat(FixtureScans.scan("filters").authoritySource().detail()).isEqualTo("HTTP Basic");
    }

    @Test
    void aChainOfTheWebStackTheApplicationDoesNotRunAddsNoWayIn() {
        assertThat(FixtureScans.scan("filterotherstack").authoritySource().detail()).isEqualTo("HTTP Basic");
    }
}
