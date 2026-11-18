package fixtures.authserverextensions;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

/**
 * An authorization server that extends Spring's: clients kept in a field, one copied from another, one finished by a
 * helper, scopes from settings or a consumer that removes some; its own token generator, token endpoint providers and
 * validator; clients registered at run time; customizers that write claims they name at run time.
 */
@SpringBootApplication
class AuthServerExtensionsApp {

    private static final Consumer<Set<String>> DEFAULT_SCOPES = scopes -> scopes.add("profile");

    private final RegisteredClientRepository clients = new InMemoryRegisteredClientRepository(clients(
            System.getProperty("partner.scope")));

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        return clients;
    }

    private static List<RegisteredClient> clients(String partnerScope) {
        RegisteredClient web = RegisteredClient.withId("web").clientId("web")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scopes(scopes -> scopes.addAll(Arrays.asList("openid", "orders.read")))
                .build();
        RegisteredClient mobile = RegisteredClient.from(web).clientId("mobile").build();
        RegisteredClient.Builder reports = RegisteredClient.withId("reports").clientId(System.getenv("REPORTS"));
        grants(reports);
        RegisteredClient trimmed = RegisteredClient.withId("trimmed").clientId("trimmed")
                .scopes(scopes -> scopes.remove("openid")).build();
        RegisteredClient partner = RegisteredClient.withId("partner").clientId("partner")
                .scopes(scopes -> scopes.addAll(Set.of("partner.read", partnerScope))).build();
        RegisteredClient kiosk = RegisteredClient.withId("kiosk").clientId("kiosk").scopes(DEFAULT_SCOPES).build();
        return List.of(web, mobile, reports.build(), trimmed, partner, kiosk);
    }

    private static void grants(RegisteredClient.Builder builder) {
        builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("reports.read");
    }

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServer(HttpSecurity http) throws Exception {
        http.oauth2AuthorizationServer(server -> server
                .tokenGenerator(new ScopedTokens())
                .tokenEndpoint(token -> token.authenticationProviders(providers -> providers.forEach(provider -> {
                    if (provider instanceof OAuth2ClientCredentialsAuthenticationProvider credentials) {
                        credentials.setAuthenticationValidator(context -> { });
                    }
                })))
                .oidc(oidc -> oidc.clientRegistrationEndpoint(Customizer.withDefaults())));
        return http.build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tenant() {
        return context -> context.getClaims().claim(System.getProperty("tenant.claim"), "acme");
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> extras() {
        return context -> context.getClaims().claims(claims -> claims.put("extra", "yes"));
    }
}

/**
 * Tokens with the client's scopes, made by the application.
 */
class ScopedTokens implements OAuth2TokenGenerator<OAuth2Token> {

    @Override
    public OAuth2Token generate(OAuth2TokenContext context) {
        if (context.getRegisteredClient().getScopes().isEmpty()) {
            throw new IllegalStateException("a client with no scopes");
        }
        return null;
    }
}

/**
 * Something the server's clients are looked up by.
 */
interface ClientLookup {

    RegisteredClient find(String id);
}
