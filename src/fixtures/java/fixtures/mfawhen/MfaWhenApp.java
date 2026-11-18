package fixtures.mfawhen;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.authorization.MultiFactorCondition;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-07 with when = WEBAUTHN_REGISTERED: only users with a passkey need the factors.
 */
@Configuration
@EnableWebSecurity
@EnableMultiFactorAuthentication(authorities = { FactorGrantedAuthority.PASSWORD_AUTHORITY,
        FactorGrantedAuthority.WEBAUTHN_AUTHORITY }, when = MultiFactorCondition.WEBAUTHN_REGISTERED)
class MfaWhenConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("USER"));
        return http.build();
    }
}

@RestController
class MfaWhenController {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
