package fixtures.authservercustom;

import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0049: the reference configuration, an authorization server chain of the application's own with OIDC and
 * the device flow, a token endpoint moved by AuthorizationServerSettings, and a JWKSource.
 */
@Configuration
@EnableWebSecurity
class CustomAuthServerApp {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2AuthorizationServer(authorizationServer -> {
            http.securityMatcher(authorizationServer.getEndpointsMatcher());
            authorizationServer.oidc(Customizer.withDefaults())
                    .deviceAuthorizationEndpoint(Customizer.withDefaults())
                    .deviceVerificationEndpoint(Customizer.withDefaults());
        }).authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().tokenEndpoint("/token").build();
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        return (selector, context) -> List.of();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("device").clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE).scope("openid").build());
    }
}

@RestController
class HelloController {

    @GetMapping("/api/hello")
    String hello() {
        return "hello";
    }
}
