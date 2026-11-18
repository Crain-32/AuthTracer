package fixtures.mfa;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-07: @EnableMultiFactorAuthentication makes every rule the DSL and pre/post build also need both factors. Its
 * factory replaces the RoleHierarchy bean, so ADMIN no longer implies USER.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableMultiFactorAuthentication(authorities = { FactorGrantedAuthority.PASSWORD_AUTHORITY,
        FactorGrantedAuthority.OTT_AUTHORITY })
class MfaConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/public").permitAll()
                .requestMatchers("/signup").anonymous()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
    }
}

@Service
class ReportService {

    @PreAuthorize("hasRole('USER')")
    String report() {
        return "report";
    }
}

@RestController
class MfaController {

    private final ReportService reports;

    MfaController(ReportService reports) {
        this.reports = reports;
    }

    @GetMapping("/public")
    String open() {
        return "open";
    }

    @GetMapping("/signup")
    String signup() {
        return "signup";
    }

    @GetMapping("/admin/users")
    String admin() {
        return "admin";
    }

    @GetMapping("/report")
    String report() {
        return reports.report();
    }
}
