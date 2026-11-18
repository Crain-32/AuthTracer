package fixtures.factoryhttp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A factory for authorizeHttpRequests only: it is handed the RoleHierarchy bean, keeps ROLE_, and adds an
 * authorization the graph can't show. Pre/post keeps using the RoleHierarchy bean directly.
 */
@Configuration
@EnableMethodSecurity
class FactoryHttpApp {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_STAFF");
    }

    @Bean
    static AuthorizationManagerFactory<RequestAuthorizationContext> requestFactory(RoleHierarchy roleHierarchy) {
        DefaultAuthorizationManagerFactory<RequestAuthorizationContext> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setRoleHierarchy(roleHierarchy);
        factory.setAdditionalAuthorization(AuthorityAuthorizationManager.hasAuthority("FACTOR_OTT"));
        return factory;
    }

    /**
     * Only for MethodInvocation: an inline hierarchy, which pre/post would use if this were its only factory.
     */
    @Bean
    static AuthorizationManagerFactory<org.aopalliance.intercept.MethodInvocation> methodFactory() {
        DefaultAuthorizationManagerFactory<org.aopalliance.intercept.MethodInvocation> factory =
                new DefaultAuthorizationManagerFactory<>();
        factory.setRoleHierarchy(RoleHierarchyImpl.fromHierarchy("ROLE_LEAD > ROLE_STAFF"));
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
class FactoryHttpController {

    private final LeadService leads;

    FactoryHttpController(LeadService leads) {
        this.leads = leads;
    }

    @GetMapping("/staff/list")
    String list() {
        return "staff";
    }

    @GetMapping("/pre")
    String pre() {
        return leads.pre();
    }
}

@Service
class LeadService {

    @PreAuthorize("hasRole('STAFF')")
    String pre() {
        return "pre";
    }
}
