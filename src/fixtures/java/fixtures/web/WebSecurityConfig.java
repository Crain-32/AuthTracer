package fixtures.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.ConditionalAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Configuration
class WebSecurityConfig {

    /**
     * Only covers /partner/**, and runs first.
     */
    /**
     * Ignored requests skip both chains, even /items/** where a role is required.
     */
    @Bean
    WebSecurityCustomizer ignoreAssets() {
        return web -> web.ignoring()
                .requestMatchers("/assets/**")
                .requestMatchers(HttpMethod.GET, "/items/feed");
    }

    @Bean
    @Order(1)
    SecurityFilterChain partnerApi(HttpSecurity http) throws Exception {
        http.securityMatcher("/partner/**")
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().hasAuthority("SCOPE_partner"))
                .httpBasic(basic -> { });
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/public/**", "/health").permitAll()
                        // whenFalse defaults to permitAll: anyone who fails the condition gets in.
                        .requestMatchers("/beta/**").access(ConditionalAuthorizationManager
                                .<RequestAuthorizationContext>when(auth -> auth.getName().startsWith("beta-"))
                                .whenTrue(AuthorityAuthorizationManager.hasRole("TESTER"))
                                .build())
                        .requestMatchers("/audit/**").access(ConditionalAuthorizationManager
                                .<RequestAuthorizationContext>when(auth -> auth.getName().endsWith("@corp"))
                                .whenTrue(AuthorityAuthorizationManager.hasRole("AUDITOR"))
                                .whenFalse(AuthenticatedAuthorizationManager.authenticated())
                                .build())
                        .requestMatchers("/ops/**").access(AuthorizationManagers.anyOf(
                                AuthorityAuthorizationManager.hasRole("OPS"),
                                AuthorityAuthorizationManager.hasAuthority("SCOPE_ops")))
                        .requestMatchers(HttpMethod.DELETE, "/items/**").hasRole("ADMIN")
                        .requestMatchers("/items/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/reports/**").access(
                                new WebExpressionAuthorizationManager("hasRole('AUDITOR') and isAuthenticated()"))
                        .requestMatchers("/items/archive/**").denyAll())
                .formLogin(form -> { });
        return http.build();
    }
}
