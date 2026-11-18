package fixtures.waysin;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Ways in beside a form: a magic link (one-time token), a passkey, the servlet container's own login, and a
 * remember-me cookie. Each keeps the user in the session once they are in.
 */
@Configuration
@EnableWebSecurity
class WaysInSecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain links(HttpSecurity http) throws Exception {
        http.securityMatcher("/links/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .oneTimeTokenLogin(withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain passkeys(HttpSecurity http) throws Exception {
        http.securityMatcher("/passkeys/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .webAuthn(webAuthn -> webAuthn.rpName("Fixture").rpId("example.com")
                        .allowedOrigins(Set.of("https://example.com")));
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain container(HttpSecurity http) throws Exception {
        http.securityMatcher("/container/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("USER"))
                .jee(jee -> jee.mappableRoles("USER", "ADMIN"));
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain returning(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .rememberMe(remember -> remember.key("fixture"));
        return http.build();
    }
}

@RestController
class WaysInController {

    @GetMapping("/links/inbox")
    String links() {
        return "links";
    }

    @GetMapping("/passkeys/inbox")
    String passkeys() {
        return "passkeys";
    }

    @GetMapping("/container/inbox")
    String container() {
        return "container";
    }
}
