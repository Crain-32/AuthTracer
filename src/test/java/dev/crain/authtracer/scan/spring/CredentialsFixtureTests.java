package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class CredentialsFixtureTests {

    @Test
    void eachClientsCredentials() {
        Map<String, String> found = credentials(FixtureScans.scan("relay"));
        assertThat(found).containsEntry("/relay/webclient", "RELAY ServletBearerExchangeFilterFunction")
                // Spring Security 7.1.1's interceptor sends no token when the request names no registration.
                .containsEntry("/relay/oauth2", "NONE OAuth2ClientHttpRequestInterceptor, but the request names no"
                        + " client registration")
                .containsEntry("/relay/static", "STATIC StaticCalls")
                .containsEntry("/relay/plain", "NONE null")
                .containsEntry("/relay/custom", "RELAY CopyAuthorizationInterceptor")
                .containsEntry("/relay/lambda", "RELAY interceptor lambda in LambdaRelay")
                .containsEntry("/relay/library", "UNKNOWN VendorInterceptor")
                .containsEntry("/partner/data", "OAUTH2_CLIENT @ClientRegistrationId(\"partner\")")
                // The registration's grant type: an authorization code token is the signed-in user's.
                .containsEntry("/relay/user", "RELAY clientRegistrationId(\"user-login\"), the signed-in user's"
                        + " authorization_code token")
                .containsEntry("/relay/service", "OAUTH2_CLIENT clientRegistrationId(\"backend\")");
    }

    @Test
    void customizerBeansApplyToClientsBuiltFromBootsBuilder() {
        assertThat(credentials(FixtureScans.scan("relaycustomizer")))
                .containsEntry("/customized", "RELAY RelayInterceptor");
    }

    @Test
    void aCallHasTheCredentialsOfTheClientBeanItIsGiven() {
        assertThat(credentials(FixtureScans.scan("relaybeans")))
                .containsEntry("/orders", "NONE OAuth2ClientHttpRequestInterceptor, but the request names no client"
                        + " registration")
                .containsEntry("/profiles", "RELAY ServletBearerExchangeFilterFunction")
                .containsEntry("/some", "UNKNOWN one of several client beans");
    }

    @Test
    void credentialsSetInOtherWays() {
        assertThat(credentials(FixtureScans.scan("credentialforms")))
                // Its own interceptor, whichever of the two client beans it is given.
                .containsEntry("/keyed", "STATIC ApiKeyInterceptor")
                // A token from an application interface nothing implements: AuthTracer can't tell (decision 0083
                // amended).
                .containsEntry("/tokened", "UNKNOWN interceptor lambda in TokenCalls: the Authorization value comes"
                        + " from TokenSource#token, which AuthTracer can't follow")
                .containsEntry("/partner/orders", "OAUTH2_CLIENT @ClientRegistrationId(\"partner\")");
        // A customizer component class applies to the clients Boot's builder makes, an abstract class's too.
        assertThat(credentials(FixtureScans.scan("credentialcustomizer")))
                .containsEntry("/catalog/{section}", "STATIC PartnerCustomizer");
        // Spring Security's own group configurer bean: its ClientRegistrationIdProcessor names the method's
        // @ClientRegistrationId, and with none its interceptor sends no token (7.1.1).
        assertThat(credentials(FixtureScans.scan("credentialgroups")))
                .containsEntry("/partner/orders", "NONE OAuth2RestClientHttpServiceGroupConfigurer, but the method"
                        + " names no @ClientRegistrationId");
    }

    private static Map<String, String> credentials(ApplicationGraph graph) {
        return graph.nodes(Egress.class).stream().collect(Collectors.toMap(Egress::uriTemplate,
                egress -> egress.credentials() + " " + egress.credentialsVia(), (a, b) -> a));
    }

}
