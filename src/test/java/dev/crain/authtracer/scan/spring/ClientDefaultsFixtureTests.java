package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0083 and OAUTH-05: client beans whose OAuth2 support sends a token without the request naming a
 * registration, and the beans a call's client is told apart by.
 */
class ClientDefaultsFixtureTests {

    private final Map<String, String> credentials = FixtureScans.scan("clientdefaults").nodes(Egress.class).stream()
            .collect(Collectors.toMap(Egress::uriTemplate, egress -> egress.credentials() + " "
                    + egress.credentialsVia()));

    @Test
    void theSignedInUsersAuthorizedClientByDefaultRelaysTheirLogin() {
        assertThat(credentials).containsEntry("/profiles/me", "RELAY ServletOAuth2AuthorizedClientExchangeFilterFunction"
                + ".setDefaultOAuth2AuthorizedClient: the signed-in user's OAuth2 client");
    }

    @Test
    void aRegistrationResolverOrADefaultFromTheEnvironmentSendsAToken() {
        assertThat(credentials)
                .containsEntry("/invoices", "OAUTH2_CLIENT OAuth2ClientHttpRequestInterceptor"
                        + ".setClientRegistrationIdResolver")
                .containsEntry("/tenants", "OAUTH2_CLIENT ServletOAuth2AuthorizedClientExchangeFilterFunction"
                        + ".setDefaultClientRegistrationId");
    }

    @Test
    void aFieldTakesTheBeanItIsNamedForAlsoWhenTheBeanIsNamedApartFromItsMethod() {
        assertThat(credentials).containsEntry("/audit", "STATIC BasicAuthenticationInterceptor");
    }

    @Test
    void aBeanAFactoryMakesHasWhatItsOwnMethodSets() {
        assertThat(credentials).containsEntry("/archive", "NONE null");
    }

    @Test
    void aFieldThatNamesNoneOfSeveralBeansIsUnknown() {
        assertThat(credentials).containsEntry("/any", "UNKNOWN one of several client beans");
    }
}
