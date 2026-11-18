package fixtures.roles;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
class RolesSecurityConfig {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("""
                ROLE_ADMIN > ROLE_STAFF
                ROLE_STAFF > ROLE_USER > ROLE_GUEST
                """);
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/staff/**").hasRole("STAFF")
                        .requestMatchers("/legacy/**").access(new WebExpressionAuthorizationManager("hasRole('USER')"))
                        .requestMatchers("/both/**").hasAllRoles("USER", "AUDITOR")
                        .anyRequest().authenticated())
                .httpBasic(basic -> { });
        return http.build();
    }
}
