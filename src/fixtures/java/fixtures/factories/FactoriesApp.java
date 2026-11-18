package fixtures.factories;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A generic factory bean serves authorizeHttpRequests and pre/post alike, and replaces the RoleHierarchy and
 * GrantedAuthorityDefaults beans for them. @Secured and @RolesAllowed still use those beans.
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
class FactoriesApp {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_STAFF");
    }

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("GRP_");
    }

    @Bean
    static <T> AuthorizationManagerFactory<T> authorizationManagerFactory() {
        DefaultAuthorizationManagerFactory<T> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setRolePrefix("AUTH_");
        return factory;
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/staff/**").hasRole("STAFF")
                        .anyRequest().authenticated())
                .httpBasic(basic -> { });
        return http.build();
    }
}

@RestController
class FactoriesController {

    private final StaffService staff;

    FactoriesController(StaffService staff) {
        this.staff = staff;
    }

    @GetMapping("/staff/list")
    String list() {
        return "staff";
    }

    @GetMapping("/pre")
    String pre() {
        return staff.pre();
    }

    @GetMapping("/pre/prefixed")
    String prefixed() {
        return staff.prefixed();
    }

    @GetMapping("/secured")
    String secured() {
        return staff.secured();
    }

    @GetMapping("/jsr250")
    String jsr250() {
        return staff.jsr250();
    }
}

@Service
class StaffService {

    @PreAuthorize("hasRole('STAFF')")
    String pre() {
        return "pre";
    }

    /**
     * Written with GrantedAuthorityDefaults' prefix: the expression root takes it off, the factory adds its own.
     */
    @PreAuthorize("hasRole('GRP_STAFF')")
    String prefixed() {
        return "prefixed";
    }

    @Secured("ROLE_STAFF")
    String secured() {
        return "secured";
    }

    @RolesAllowed("STAFF")
    String jsr250() {
        return "jsr250";
    }
}
