package fixtures.servletpath;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The DispatcherServlet is mapped to /api (application.properties) and the application declares no
 * PathPatternRequestMatcher.Builder: Boot's own adds /api to every String pattern.
 */
@SpringBootApplication
class ServletPathApp {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class ServletPathController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/public/info")
    String info() {
        return "info";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
