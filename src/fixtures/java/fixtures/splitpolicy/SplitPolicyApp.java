package fixtures.splitpolicy;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0027: a Split asks for what its parts ask for. The RoleHierarchy bean (ROLE_ADMIN > ROLE_STAFF) is not
 * the one pre/post uses: its factory's is ROLE_LEAD > ROLE_STAFF.
 */
@Configuration
@EnableMethodSecurity
class SplitPolicyApp {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_STAFF");
    }

    @Bean
    static AuthorizationManagerFactory<MethodInvocation> methodFactory() {
        DefaultAuthorizationManagerFactory<MethodInvocation> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setRoleHierarchy(RoleHierarchyImpl.fromHierarchy("ROLE_LEAD > ROLE_STAFF"));
        return factory;
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@Service
class ReportService {

    @PreAuthorize("hasRole('STAFF')")
    String summary() {
        return "summary";
    }

    @PreAuthorize("hasRole('AUDITOR')")
    String audit() {
        return "audit";
    }
}

@RestController
class ReportController {

    private final ReportService reports;

    ReportController(ReportService reports) {
        this.reports = reports;
    }

    @GetMapping("/report")
    String report(@RequestParam boolean audit) {
        if (audit) {
            return reports.audit();
        }
        return reports.summary();
    }
}
