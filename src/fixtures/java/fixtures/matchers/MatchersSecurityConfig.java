package fixtures.matchers;

import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

@Configuration
class MatchersSecurityConfig {

    /**
     * A top-level customizer for authorizeHttpRequests: its rules come before every chain's own.
     */
    @Bean
    Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> ops() {
        return authorize -> authorize.requestMatchers("/ops/**").hasRole("OPS");
    }

    @Bean
    @Order(1)
    SecurityFilterChain partners(HttpSecurity http) throws Exception {
        http.securityMatchers(matchers -> matchers
                        .requestMatchers("/partner/**")
                        .requestMatchers(HttpMethod.POST, "/hooks/**"))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasAuthority("SCOPE_partner"));
        return http.build();
    }

    /**
     * securityMatcher(String) replaces the one before it: only /new/** reaches this chain.
     */
    @Bean
    @Order(2)
    SecurityFilterChain replaced(HttpSecurity http) throws Exception {
        http.securityMatcher("/old/**")
                .securityMatcher("/new/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll());
        return http.build();
    }

    /**
     * Published as a bean, so expressions can reference other beans with @name.
     */
    @Bean
    WebExpressionAuthorizationManager.Builder expressions() {
        return WebExpressionAuthorizationManager.withDefaults();
    }

    @Bean
    @Order(3)
    SecurityFilterChain app(HttpSecurity http, WebExpressionAuthorizationManager.Builder expressions) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        // No trailing .*: /admin/users?x=1 doesn't match and falls through to anyRequest().
                        .requestMatchers(RegexRequestMatcher.regexMatcher("/admin/[a-z]+")).hasRole("ADMIN")
                        .requestMatchers(RegexRequestMatcher.regexMatcher(HttpMethod.GET, "/reports/[0-9]+(\\?.*)?"))
                        .hasRole("AUDITOR")
                        .requestMatchers(new RegexRequestMatcher("/docs.*", null)).permitAll()
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                        .requestMatchers(PathPatternRequestMatcher.withDefaults().basePath("/legacy").matcher("/items"))
                        .hasRole("LEGACY")
                        .requestMatchers("/expr").access(WebExpressionAuthorizationManager.withDefaults()
                                .expression("hasRole('EXPR')"))
                        .requestMatchers("/expr/bean").access(expressions.expression("hasRole('BEAN')"))
                        .anyRequest().authenticated())
                .httpBasic(basic -> { });
        return http.build();
    }
}
