package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0083 amended: each of the clients one method builds has what is set on it, and the Authorization value an
 * interceptor sets is followed back through fields, parameters and other classes.
 */
class ClientBuildsFixtureTests {

    @Test
    void twoClientsBuiltInOneMethodEachHaveTheirOwn() {
        assertThat(credentials(FixtureScans.scan("clientbuilds")))
                .containsEntry("/two/relayed", "RELAY BearerRelay").containsEntry("/two/plain", "NONE null")
                .containsEntry("/fields/keyed", "STATIC FieldClients").containsEntry("/fields/open", "NONE null")
                .containsEntry("/templates/relayed", "RELAY BearerRelay")
                .containsEntry("/templates/plain", "NONE null")
                .containsEntry("/web/reports", "OAUTH2_CLIENT ServletOAuth2AuthorizedClientExchangeFilterFunction"
                        + ".setDefaultClientRegistrationId(\"reports\")")
                .containsEntry("/web/open", "NONE null");
    }

    @Test
    void whatIsSetOnABuilderTwoClientsShareIsOnBoth() {
        assertThat(credentials(FixtureScans.scan("clientbuilds"))).containsEntry("/shared/first", "RELAY BearerRelay")
                .containsEntry("/shared/second", "RELAY BearerRelay");
    }

    @Test
    void theAuthorizationValueIsFollowedToWhereItComesFrom() {
        assertThat(credentials(FixtureScans.scan("tokentrace")))
                .containsEntry("/held", "RELAY HolderInterceptor: the caller's token, from"
                        + " CaptureFilter#doFilterInternal")
                .containsEntry("/provided", "RELAY interceptor lambda in ProviderCalls: the caller's token, from"
                        + " ContextTokens#token")
                .containsEntry("/configured", "STATIC KeyInterceptor")
                .containsEntry("/fetched", "OAUTH2_CLIENT interceptor lambda in FetchCalls: an authorized client's"
                        + " token, from ClientTokens#fetch")
                .containsEntry("/late", "UNKNOWN interceptor lambda in LateCalls: the Authorization value comes from"
                        + " the field LateTokens.token, which AuthTracer can't follow");
    }

    private static Map<String, String> credentials(ApplicationGraph graph) {
        return graph.nodes(Egress.class).stream().collect(Collectors.toMap(Egress::uriTemplate,
                egress -> egress.credentials() + " " + egress.credentialsVia(), (a, b) -> a));
    }
}
