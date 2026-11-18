package fixtures.variableroutes;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A rule narrower than a route with a variable takes part of its requests: /reports/public-q1 reaches the report
 * handler under permitAll. /users/me has a handler of its own, which Spring MVC picks for that path.
 */
@Configuration
@EnableWebSecurity
class VariableRoutesConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/reports/public-*").permitAll()
                .requestMatchers("/users/me").permitAll()
                .anyRequest().hasRole("ADMIN"));
        return http.build();
    }
}

@RestController
class VariableRoutesController {

    @GetMapping("/reports/{type}")
    String report(@PathVariable String type) {
        return type;
    }

    @GetMapping("/users/{id}")
    String user(@PathVariable String id) {
        return id;
    }

    @GetMapping("/users/me")
    String me() {
        return "me";
    }
}
