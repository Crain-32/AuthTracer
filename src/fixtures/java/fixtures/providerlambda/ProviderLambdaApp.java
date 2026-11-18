package fixtures.providerlambda;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A resource server whose tokens a lambda of the application's checks, instead of Spring's JWT provider: its
 * converter's mapping is not what the requests carry.
 */
@Configuration
@EnableWebSecurity
class ProviderLambdaSecurityConfig {

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri("https://idp.example.com/jwks").build();
    }

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("ADMIN"))
                .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.authenticationManager(authentication -> {
                    throw new BadCredentialsException("checked elsewhere");
                })));
        return http.build();
    }
}

@RestController
class ProviderLambdaController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }
}
