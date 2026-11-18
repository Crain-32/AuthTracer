package fixtures.mfareferences;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0093: factors asked for with method references to RequiredFactor.Builder's shorthands, and a factory
 * given an AuthenticationTrustResolver of its own.
 */
@Configuration
@EnableWebSecurity
class MfaReferencesConfig {

    @Bean
    AuthorizationManagerFactory<Object> authorizationManagerFactory() {
        DefaultAuthorizationManagerFactory<Object> factory = AuthorizationManagerFactories.multiFactor()
                .requireFactor(RequiredFactor.Builder::passwordAuthority)
                .build();
        factory.setTrustResolver(new AuthenticationTrustResolverImpl());
        return factory;
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        AllRequiredFactorsAuthorizationManager<RequestAuthorizationContext> passkey = AllRequiredFactorsAuthorizationManager
                .<RequestAuthorizationContext>builder()
                .requireFactor(RequiredFactor.Builder::webauthnAuthority)
                .build();
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/keys/**").access(passkey)
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class MfaReferencesController {

    @GetMapping("/keys/rotate")
    String rotate() {
        return "rotated";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
