package fixtures.basepathunread;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The Builder bean computes its base path from the DispatcherServlet's property, which AuthTracer doesn't follow.
 */
@SpringBootApplication
class BasePathUnreadApp {

    @Bean
    PathPatternRequestMatcher.Builder mvc(@Value("${spring.mvc.servlet.path}") String servletPath) {
        return PathPatternRequestMatcher.withDefaults().basePath(servletPath.strip());
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class BasePathUnreadController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }
}
