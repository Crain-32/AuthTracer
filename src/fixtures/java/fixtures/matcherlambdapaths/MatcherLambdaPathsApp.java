package fixtures.matcherlambdapaths;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP-06 under a context path and a DispatcherServlet path (application.properties): the servlet path is only what
 * follows /api, and the raw URI starts with /app, so lambdas that test either can't be read against the routes.
 */
@Configuration
@EnableWebSecurity
class MatcherLambdaPathsConfig {

    @Bean
    SecurityFilterChain paths(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(request -> request.getServletPath().startsWith("/admin")).hasRole("ADMIN")
                .requestMatchers(request -> request.getRequestURI().startsWith("/app/api/reports")).hasRole("REPORTS")
                .requestMatchers(request -> "GET".equals(request.getMethod())).hasRole("READER")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class MatcherLambdaPathsController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }
}
