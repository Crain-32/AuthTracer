package fixtures.x509;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Callers present a client certificate; its subject is looked up on every request.
 */
@Configuration
@EnableWebSecurity
@RestController
class X509Application {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("USER")).x509(withDefaults());
        return http.build();
    }

    @GetMapping("/whoami")
    String whoami() {
        return "you";
    }
}
