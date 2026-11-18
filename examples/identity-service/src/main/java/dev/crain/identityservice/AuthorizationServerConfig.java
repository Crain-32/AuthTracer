package dev.crain.identityservice;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Users and the registered clients for the local identity provider.
 * <p>
 * The security filter chains (authorization server endpoints + form login), the JWK source
 * and the issuer settings all come from Spring Boot auto-configuration; Boot only needs a
 * {@link RegisteredClientRepository} bean to switch the authorization server on.
 */
@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {

    static final String CLIENT_ID = "authtracer-driver";
    static final String CLIENT_SECRET = "driver-secret";
    static final String REDIRECT_URI = "http://127.0.0.1:8099/callback";
    static final String USER_PASSWORD = "password";

    /**
     * payroll-service itself, for work no user asked for: its Kafka listener reads employees from employee-service.
     */
    static final String PAYROLL_CLIENT_ID = "payroll-service";
    static final String PAYROLL_CLIENT_SECRET = "payroll-secret";

    /**
     * Shared by form login (user passwords) and client authentication (client secret).
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        String encoded = passwordEncoder.encode(USER_PASSWORD);
        return new InMemoryUserDetailsManager(
                User.withUsername("alice").password(encoded).roles("USER").build(),
                User.withUsername("bob").password(encoded).roles("USER").build(),
                User.withUsername("carol").password(encoded).roles("USER", "AUDITOR").build(),
                User.withUsername("admin").password(encoded).roles("USER", "ADMIN").build());
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient driver = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(CLIENT_ID)
                .clientSecret(passwordEncoder.encode(CLIENT_SECRET))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("employees.read")
                .scope("employees.write")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        // Spring Security 7 defaults requireProofKey to true. The contract does not
                        // require PKCE, so make it optional: a code_challenge is still verified if sent.
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .build();
        // A service's own client: client credentials only, and only the scope it needs to read employees. Its tokens
        // name the service, not a user, so they carry no roles.
        RegisteredClient payroll = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(PAYROLL_CLIENT_ID)
                .clientSecret(passwordEncoder.encode(PAYROLL_CLIENT_SECRET))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("employees.read")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(driver, payroll);
    }

}
