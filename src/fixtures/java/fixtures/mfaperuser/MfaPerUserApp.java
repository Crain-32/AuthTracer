package fixtures.mfaperuser;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.MapRequiredAuthoritiesRepository;
import org.springframework.security.authorization.RequiredAuthoritiesAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-10: a RequiredAuthoritiesAuthorizationManager asks the admin user for a one-time token too.
 */
@Configuration
@EnableWebSecurity
class MfaPerUserConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    AuthorizationManagerFactory<Object> authorizationManagerFactory(
            RequiredAuthoritiesAuthorizationManager<Object> admins) {
        DefaultAuthorizationManagerFactory<Object> defaults = new DefaultAuthorizationManagerFactory<>();
        defaults.setAdditionalAuthorization(admins);
        return defaults;
    }

    @Bean
    RequiredAuthoritiesAuthorizationManager<Object> adminAuthorization() {
        MapRequiredAuthoritiesRepository authorities = new MapRequiredAuthoritiesRepository();
        authorities.saveRequiredAuthorities("admin", List.of(FactorGrantedAuthority.OTT_AUTHORITY));
        return new RequiredAuthoritiesAuthorizationManager<>(authorities);
    }
}

@RestController
class MfaPerUserController {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
