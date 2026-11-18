package fixtures.providerbasic;

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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP Basic, checked by a provider the chain is given: whatever it looks up, on every request.
 */
@Configuration
@EnableWebSecurity
class ProviderBasicSecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("PARTNER"))
                .httpBasic(withDefaults())
                .authenticationProvider(new ApiKeyProvider());
        return http.build();
    }
}

class ApiKeyProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) {
        return UsernamePasswordAuthenticationToken.authenticated(authentication.getName(), null,
                AuthorityUtils.createAuthorityList("ROLE_PARTNER"));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}

@RestController
class ProviderBasicController {

    @GetMapping("/orders")
    String orders() {
        return "orders";
    }
}
