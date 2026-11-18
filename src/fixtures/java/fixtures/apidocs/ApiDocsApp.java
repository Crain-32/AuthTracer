package fixtures.apidocs;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0054: springdoc's API docs at a configured path; the chain leaves the UI open and the docs authenticated.
 */
@SpringBootApplication
class ApiDocsApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/swagger-ui/**", "/swagger-ui.html")
                .permitAll().anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class HelloController {

    @GetMapping("/hello")
    String hello() {
        return "hello";
    }
}
