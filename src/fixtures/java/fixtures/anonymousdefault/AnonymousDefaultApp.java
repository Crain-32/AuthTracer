package fixtures.anonymousdefault;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The welcome page asks for the anonymous role by name, which Spring gives callers who haven't signed in.
 */
@Configuration
@EnableWebSecurity
class AnonymousDefaultConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/welcome").hasAnyRole("ANONYMOUS", "USER")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class WelcomeController {

    @GetMapping("/welcome")
    String welcome() {
        return "welcome";
    }
}
