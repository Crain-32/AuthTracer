package fixtures.providercomponent;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Passwords are checked against a legacy system by the application's one AuthenticationProvider bean, which the
 * global AuthenticationManager takes in place of the UserDetailsService.
 */
@Configuration
@EnableWebSecurity
class ProviderComponentSecurityConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("STAFF"))
                .formLogin(withDefaults());
        return http.build();
    }
}

@Component
class LegacyPasswordProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) {
        return UsernamePasswordAuthenticationToken.authenticated(authentication.getName(), null,
                AuthorityUtils.createAuthorityList("ROLE_STAFF"));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

@RestController
class ProviderComponentController {

    @GetMapping("/rota")
    String rota() {
        return "rota";
    }
}
