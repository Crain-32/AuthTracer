package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0083: each call has the credentials of the client it is made on, set where that client is built.
 */
class OwnClientsFixtureTests {

    private final Map<String, String> credentials = credentials(FixtureScans.scan("ownclients"));

    @Test
    void aClientTheClassBuildsFromAFactoryHasNoneOfTheBeansCredentialsOrTheCustomizers() {
        assertThat(credentials).containsEntry("/own", "NONE null").containsEntry("/own/web", "NONE null")
                .containsEntry("/own/template", "NONE null");
    }

    @Test
    void aClientBuiltFromBootsBuilderHasTheCustomizersCredentials() {
        assertThat(credentials).containsEntry("/built", "STATIC ClientBeans");
    }

    @Test
    void anInjectedClientHasItsBeansCredentials() {
        assertThat(credentials).containsEntry("/injected", "RELAY BearerRelay")
                .containsEntry("/reports", "OAUTH2_CLIENT ServletOAuth2AuthorizedClientExchangeFilterFunction"
                        + ".setDefaultClientRegistrationId(\"backend\")")
                .containsEntry("/templated", "RELAY BearerRelay");
    }

    @Test
    void anOAuth2InterceptorSendsATokenOnlyForARequestThatNamesARegistration() {
        assertThat(credentials).containsEntry("/partners/named", "OAUTH2_CLIENT clientRegistrationId(\"backend\")")
                // Spring Security adds no token, so the customizer's key is what goes.
                .containsEntry("/partners/unnamed", "STATIC ClientBeans")
                .containsEntry("/ledgers/authorized", "OAUTH2_CLIENT oauth2AuthorizedClient(..)")
                .containsEntry("/ledgers/plain", "NONE ServletOAuth2AuthorizedClientExchangeFilterFunction, but the"
                        + " request names no client registration");
    }

    @Test
    void anHttpServiceGroupHasItsConfigurersAndTheCustomizers() {
        assertThat(credentials).containsEntry("/partner/orders", "OAUTH2_CLIENT @ClientRegistrationId(\"backend\")")
                .containsEntry("/partner/catalog", "STATIC ClientBeans");
    }

    @Test
    void aHandWiredInterfaceHasItsClientsCredentialsForTheRegistrationItNames() {
        assertThat(credentials).containsEntry("/ledger", "OAUTH2_CLIENT @ClientRegistrationId(\"user-login\")");
    }

    private static Map<String, String> credentials(ApplicationGraph graph) {
        return graph.nodes(Egress.class).stream().collect(Collectors.toMap(Egress::uriTemplate,
                egress -> egress.credentials() + " " + egress.credentialsVia(), (a, b) -> a));
    }
}
