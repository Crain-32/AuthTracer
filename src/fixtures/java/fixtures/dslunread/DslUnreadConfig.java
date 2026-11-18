package fixtures.dslunread;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Rules written in ways the DSL reader can't fully read: a negation, a path variable compared with the caller, a role
 * that isn't a constant, rules set in a helper method and from a customizer a method returns.
 */
@Configuration
class DslUnreadConfig {

    enum Role {
        ADMIN
    }

    @Bean
    @Order(1)
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/**");
        apiRules(http);
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain ops(HttpSecurity http) throws Exception {
        http.securityMatcher("/ops/**").authorizeHttpRequests(opsRules());
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/internal/**").not().hasRole("PARTNER")
                .requestMatchers("/users/{id}/**").hasVariable("id").equalTo(Authentication::getName)
                .requestMatchers("/admin/**").hasRole(Role.ADMIN.name())
                .anyRequest().permitAll());
        return http.build();
    }

    private void apiRules(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("API"));
    }

    private Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>
            opsRules() {
        return authorize -> authorize.anyRequest().hasRole("OPS");
    }
}
