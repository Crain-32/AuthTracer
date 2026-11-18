package fixtures.mfaendpoints;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-07 for some endpoints only, as the reference shows it: @EnableMultiFactorAuthentication(authorities = {})
 * registers no factory, and the admin rule builds its own.
 */
@Configuration
@EnableWebSecurity
@EnableMultiFactorAuthentication(authorities = {})
class MfaEndpointsConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        AuthorizationManagerFactory<RequestAuthorizationContext> mfa = AuthorizationManagerFactories
                .<RequestAuthorizationContext>multiFactor()
                .requireFactors(FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY)
                .build();
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").access(mfa.hasRole("ADMIN"))
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class MfaEndpointsController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
