package fixtures.authserverunread;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Clients a store of the application's keeps, one with a scope from its settings, and a customizer that grants an
 * extra scope to some tokens: a token may carry scopes no registration names.
 */
@SpringBootApplication
class AuthServerUnreadApp {

    @Bean
    RegisteredClientRepository registeredClientRepository(Map<String, String> settings) {
        return new TenantClients(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("tenant")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope(settings.get("tenant.scope"))
                .build());
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> support() {
        return context -> context.getClaims().claim("scope", List.of("support.all"));
    }
}

class TenantClients implements RegisteredClientRepository {

    private final RegisteredClient client;

    TenantClients(RegisteredClient client) {
        this.client = client;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
    }

    @Override
    public RegisteredClient findById(String id) {
        return client;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return client;
    }
}
