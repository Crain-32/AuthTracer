package fixtures.providerbeans;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Two AuthenticationProvider beans, which the global AuthenticationManager leaves out, and an AuthenticationManager
 * bean that it falls back to: a manager of Spring's, holding one provider of the application's.
 */
@Configuration
@EnableWebSecurity
class ProviderBeansSecurityConfig {

    @Bean
    AuthenticationProvider anonymous() {
        return new AnonymousAuthenticationProvider("key");
    }

    @Bean
    AuthenticationProvider returning() {
        return new RememberMeAuthenticationProvider("key");
    }

    @Bean
    AuthenticationManager authenticationManager() {
        return new ProviderManager(List.of(new TenantProvider(), new RememberMeAuthenticationProvider("key")));
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults());
        return http.build();
    }
}

class TenantProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) {
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}

@RestController
class ProviderBeansController {

    @GetMapping("/tenants")
    String tenants() {
        return "tenants";
    }
}
