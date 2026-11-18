package fixtures.webflux;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.authorization.OAuth2ReactiveAuthorizationManagers;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

@Configuration
@EnableWebFluxSecurity
class WebFluxSecurityConfig {

    /**
     * The reactive DSL's hasRole never uses it.
     */
    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_STAFF");
    }

    @Bean
    Customizer<ServerHttpSecurity> actuator() {
        return http -> http.authorizeExchange(exchange -> exchange.pathMatchers("/actuator/**").hasRole("OPS"));
    }

    @Bean
    Customizer<ServerHttpSecurity.AuthorizeExchangeSpec> ops() {
        return exchange -> exchange.pathMatchers("/ops/**").hasRole("OPS2");
    }

    @Bean
    @Order(1)
    SecurityWebFilterChain partners(ServerHttpSecurity http) {
        return http.securityMatcher(ServerWebExchangeMatchers.pathMatchers("/partner/**"))
                .authorizeExchange(exchange -> exchange.anyExchange()
                        .access(OAuth2ReactiveAuthorizationManagers.hasScope("partner")))
                .build();
    }

    @Bean
    @Order(2)
    SecurityWebFilterChain app(ServerHttpSecurity http) {
        return http.authorizeExchange(exchange -> exchange
                        .pathMatchers("/staff/**").hasRole("STAFF")
                        .pathMatchers(HttpMethod.POST, "/orders").hasAuthority("SCOPE_orders.write")
                        .matchers(new PathPatternParserServerWebExchangeMatcher("/legacy/**")).denyAll()
                        .pathMatchers("/public/**").permitAll()
                        .pathMatchers("/reports/**").access(AuthorityReactiveAuthorizationManager.hasAnyRole("AUDITOR",
                                "ADMIN"))
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }
}
