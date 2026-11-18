package fixtures.headrequests;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0110: rules for GET, and handlers mapped for GET, which Spring MVC also runs for HEAD. HEAD gets the rules
 * after the GET ones: anyone may HEAD the admin's users, a reader the reports an auditor may GET.
 */
@Configuration
@EnableWebSecurity
class HeadRequestsConfig {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.GET, "/admin/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET, "/reports/**").hasRole("AUDITOR")
                .requestMatchers("/reports/**").hasRole("READER")
                .requestMatchers(HttpMethod.GET, "/open/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class HeadRequestsController {

    /**
     * HEAD gets anyRequest's rule: anyone signed in, not only an admin.
     */
    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    /**
     * HEAD gets the rule for any method: a reader, not an auditor.
     */
    @GetMapping("/reports/daily")
    String daily() {
        return "daily";
    }

    /**
     * GET lets everyone in already: HEAD, which needs a caller signed in, asks no less.
     */
    @GetMapping("/open/info")
    String info() {
        return "info";
    }

    @GetMapping("/admin/stats")
    String stats() {
        return "stats";
    }

    /**
     * A mapping of its own for HEAD: HEAD /admin/stats runs this, not the GET handler.
     */
    @RequestMapping(path = "/admin/stats", method = RequestMethod.HEAD)
    void statsHead() {
    }
}
