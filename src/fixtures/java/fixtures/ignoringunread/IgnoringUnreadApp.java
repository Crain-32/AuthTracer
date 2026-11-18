package fixtures.ignoringunread;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0051: probes from the local machine skip security, by a matcher on the caller's address AuthTracer can't
 * evaluate.
 */
@Configuration
@EnableWebSecurity
class IgnoringUnreadConfig {

    @Bean
    WebSecurityCustomizer localProbes() {
        return web -> web.ignoring().requestMatchers(request -> request.getRemoteAddr().equals("127.0.0.1"));
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("OPS"));
        return http.build();
    }
}

@RestController
class HealthController {

    @GetMapping("/health/details")
    String details() {
        return "details";
    }
}
