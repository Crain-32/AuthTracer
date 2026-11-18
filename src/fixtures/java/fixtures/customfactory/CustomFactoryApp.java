package fixtures.customfactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * ROLE-04 with a factory of the application's own: it builds every hasRole(..) its way, which AuthTracer doesn't read.
 */
@Configuration
@EnableWebSecurity
class CustomFactoryConfig {

    @Bean
    AuthorizationManagerFactory<Object> authorizationManagerFactory() {
        return new TenantAuthorizationManagerFactory();
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}

/**
 * Roles are per tenant: hasRole("ADMIN") asks for TENANT_ADMIN.
 */
class TenantAuthorizationManagerFactory implements AuthorizationManagerFactory<Object> {

    @Override
    public AuthorizationManager<Object> hasRole(String role) {
        return AuthorityAuthorizationManager.hasAuthority("TENANT_" + role);
    }
}

@RestController
class CustomFactoryController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }
}
