package fixtures.anonymousoff;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Anonymous authentication turned off: callers who haven't signed in have no Authentication, so the sign-up page's
 * anonymous() admits no one, and the anonymous role is no one's.
 */
@Configuration
@EnableWebSecurity
class AnonymousOffConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/signup").anonymous()
                        .requestMatchers("/welcome").hasAnyRole("ANONYMOUS", "USER")
                        .anyRequest().authenticated())
                .anonymous(AbstractHttpConfigurer::disable);
        return http.build();
    }
}

@RestController
class SignupController {

    @GetMapping("/signup")
    String signup() {
        return "signup";
    }

    @GetMapping("/welcome")
    String welcome() {
        return "welcome";
    }
}
