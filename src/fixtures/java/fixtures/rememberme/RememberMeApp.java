package fixtures.rememberme;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A site with remember-me sign-in: changing the password needs a fresh sign-in, the welcome-back page is for
 * remember-me sessions only.
 */
@Configuration
@EnableMethodSecurity
class RememberMeSecurityConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/account/password").fullyAuthenticated()
                        .requestMatchers("/welcome-back").rememberMe()
                        .anyRequest().authenticated())
                .rememberMe(remember -> remember.key("fixture"));
        return http.build();
    }
}

@RestController
class AccountController {

    @PostMapping("/account/password")
    String password() {
        return "changed";
    }

    @GetMapping("/welcome-back")
    String welcomeBack() {
        return "hello again";
    }

    @GetMapping("/account/email")
    @PreAuthorize("isFullyAuthenticated()")
    String email() {
        return "me@example.com";
    }
}
