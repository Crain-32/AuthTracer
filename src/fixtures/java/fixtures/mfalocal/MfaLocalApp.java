package fixtures.mfalocal;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-08 and AUTHZ-09: factors asked for by some rules only, through a factory built in place and a factors
 * manager.
 */
@Configuration
@EnableWebSecurity
class MfaLocalConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http, AuthorizationManager<Object> recentPassword) throws Exception {
        AuthorizationManagerFactory<Object> mfa = AuthorizationManagerFactories.multiFactor()
                .requireFactors(FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY)
                .build();
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").access(mfa.hasRole("ADMIN"))
                .requestMatchers("/profile").access(recentPassword)
                .requestMatchers("/settings/**").access(AllRequiredFactorsAuthorizationManager.builder()
                        .requireFactor(factor -> factor.passwordAuthority().validDuration(Duration.ofMinutes(5)))
                        .build())
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    AuthorizationManager<Object> recentPassword() {
        return AuthorizationManagerFactories.multiFactor()
                .requireFactor(factor -> factor.passwordAuthority().validDuration(Duration.ofMinutes(5)))
                .requireFactor(factor -> factor.ottAuthority())
                .build()
                .authenticated();
    }
}

@RestController
class MfaLocalController {

    @GetMapping("/admin/users")
    String admin() {
        return "admin";
    }

    @GetMapping("/settings/password")
    String settings() {
        return "settings";
    }

    @GetMapping("/profile")
    String profile() {
        return "profile";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
