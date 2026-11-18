package fixtures.dslhelpers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Configuration split the ways real applications split it: a template method a subclass fills in, helpers that call
 * helpers, a helper that takes the rule registry, a customizer kept in a field, and paths injected from properties.
 */
abstract class BaseSecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/**");
        apiRules(http);
        return http.build();
    }

    /**
     * Which subclass fills it in is decided at run time.
     */
    protected abstract void apiRules(HttpSecurity http) throws Exception;
}

@Configuration
@EnableWebSecurity
class DslHelpersConfig extends BaseSecurityConfig {

    private final Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>
            reportRules = authorize -> authorize.anyRequest().hasRole("REPORTS");

    @Value("${security.public-paths}")
    private String[] publicPaths;

    @Override
    protected void apiRules(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("API"));
    }

    @Bean
    @Order(2)
    SecurityFilterChain admin(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**");
        hardened(http);
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain reports(HttpSecurity http) throws Exception {
        http.securityMatcher("/reports/**").authorizeHttpRequests(reportRules);
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> common(authorize)
                .requestMatchers(publicPaths).permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    private static AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry common(
            AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorize) {
        return authorize.requestMatchers("/health").permitAll();
    }

    private void hardened(HttpSecurity http) throws Exception {
        http.headers(headers -> headers.frameOptions(frame -> frame.deny()));
        sessions(http);
    }

    private void sessions(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        csrf(http);
    }

    private void csrf(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/admin/hooks/**"));
        adminRules(http);
    }

    private void adminRules(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("ADMIN"));
    }
}

@RestController
class DslHelpersController {

    @GetMapping("/api/items")
    String items() {
        return "items";
    }

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/reports/daily")
    String daily() {
        return "daily";
    }

    @GetMapping("/health")
    String health() {
        return "up";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
