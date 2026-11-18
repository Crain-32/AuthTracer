package fixtures.matcherlambdareversed;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lambda matchers that aren't the prefix or exact path tests they look like: a constant that starts with the path
 * (matches /, /a, /adm..., not /admin/x), and a path compared ignoring case (matches /OPS too).
 */
@SpringBootApplication
public class MatcherLambdaReversedApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(request -> "/admin/reports".startsWith(request.getServletPath())).hasRole("ADMIN")
                .requestMatchers(request -> request.getServletPath().equalsIgnoreCase("/ops")).hasRole("OPS")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class PagesController {

    @GetMapping("/admin")
    String admin() {
        return "admin";
    }

    @GetMapping("/ops")
    String ops() {
        return "ops";
    }
}
