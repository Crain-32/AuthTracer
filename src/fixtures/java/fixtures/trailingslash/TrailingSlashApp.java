package fixtures.trailingslash;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A mapping ending in a slash answers that path only (Spring Framework 7's PathPatternParser doesn't match an
 * optional trailing slash): /users/ and /teams/ fall to anyRequest(), not to the rules for /users and /teams.
 */
@Configuration
@EnableWebSecurity
class TrailingSlashConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/users", "/teams").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
@RequestMapping("/users")
class UsersController {

    @GetMapping("/")
    String list() {
        return "users";
    }

    @GetMapping("/{id}")
    String user(@PathVariable String id) {
        return id;
    }
}

@RestController
@RequestMapping("/teams/")
class TeamsController {

    @GetMapping
    String list() {
        return "teams";
    }

    @GetMapping("/{id}")
    String team(@PathVariable String id) {
        return id;
    }
}
