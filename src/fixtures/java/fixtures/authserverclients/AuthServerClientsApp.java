package fixtures.authserverclients;

import java.util.Set;
import java.util.UUID;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * An authorization server with two clients: a web app that signs users in, and a batch job with its own scopes; a
 * customizer adds the user's department to their tokens.
 */
@SpringBootApplication
class AuthServerClientsApp {

    static final String DEPARTMENT = "department";

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient web = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("web")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://web.example.com/login/oauth2/code/web")
                .scope(OidcScopes.OPENID)
                .scope("orders.read")
                .build();
        RegisteredClient batch = batch();
        return new InMemoryRegisteredClientRepository(web, batch);
    }

    private static RegisteredClient batch() {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString());
        builder.clientId("batch");
        builder.clientSecret("{noop}secret");
        builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
        builder.scopes(scopes -> scopes.addAll(Set.of("orders.read", "orders.export")));
        return builder.build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> departments() {
        return context -> context.getClaims().claim(DEPARTMENT, "sales");
    }
}
