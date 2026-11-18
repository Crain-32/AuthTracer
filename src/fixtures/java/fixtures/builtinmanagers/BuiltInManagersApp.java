package fixtures.builtinmanagers;

import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AllAuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring Security's built-in managers given to {@code access(..)}: each factory and overload, composed with
 * {@code AuthorizationManagers}, a default decision for when every manager abstains, a role that isn't a constant, and
 * a manager given the RoleHierarchy, which the factories' managers don't have.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class BuiltInManagersConfig {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_OPS");
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http, @Value("${team.role}") String role, RoleHierarchy roleHierarchy)
            throws Exception {
        AuthorityAuthorizationManager<RequestAuthorizationContext> operators = AuthorityAuthorizationManager
                .hasRole("OPS");
        operators.setRoleHierarchy(roleHierarchy);
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/hierarchical/**").access(operators)
                .requestMatchers("/flat/**").access(AuthorityAuthorizationManager.hasRole("OPS"))
                .requestMatchers("/prefixed/**")
                .access(AuthorityAuthorizationManager.hasAnyRole("GROUP_", new String[] {"OPS", "SRE"}))
                .requestMatchers("/all-roles/**")
                .access(AllAuthoritiesAuthorizationManager.hasAllRoles("TELLER", "AUDITOR"))
                .requestMatchers("/all-prefixed/**")
                .access(AllAuthoritiesAuthorizationManager.hasAllPrefixedAuthorities("GROUP_", "OPS", "SRE"))
                .requestMatchers("/either/**").access(AuthorizationManagers.anyOf(
                        AuthorityAuthorizationManager.hasRole("ADMIN"),
                        AuthorityAuthorizationManager.hasAuthority("SCOPE_reports")))
                .requestMatchers("/abstaining/**").access(AuthorizationManagers.anyOf(new AuthorizationDecision(true),
                        AuthorityAuthorizationManager.hasRole("ADMIN"), new Abstaining()))
                .requestMatchers("/both/**").access(AuthorizationManagers.allOf(new AuthorizationDecision(false),
                        AuthorityAuthorizationManager.hasRole("ADMIN"),
                        AuthenticatedAuthorizationManager.fullyAuthenticated()))
                .requestMatchers("/members/**")
                .access(AuthorizationManagers.not(AuthenticatedAuthorizationManager.anonymous()))
                .requestMatchers("/guests/**").anonymous()
                .requestMatchers("/open/**").access(SingleResultAuthorizationManager.permitAll())
                .requestMatchers("/scoped/**").access(OAuth2AuthorizationManagers.hasAllScopes("read", "write"))
                .requestMatchers("/team/**").hasAnyRole("LEAD", role)
                .anyRequest().authenticated());
        return http.build();
    }
}

/**
 * Abstains: the default decision answers.
 */
class Abstaining implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return null;
    }
}

@RestController
class BuiltInManagersController {

    @GetMapping("/prefixed/run")
    String prefixed() {
        return "prefixed";
    }

    @GetMapping("/all-roles/run")
    String allRoles() {
        return "all roles";
    }

    @GetMapping("/all-prefixed/run")
    String allPrefixed() {
        return "all prefixed";
    }

    @GetMapping("/either/run")
    String either() {
        return "either";
    }

    @GetMapping("/abstaining/run")
    String abstaining() {
        return "abstaining";
    }

    @GetMapping("/both/run")
    String both() {
        return "both";
    }

    @GetMapping("/members/run")
    String members() {
        return "members";
    }

    @GetMapping("/guests/run")
    @PreAuthorize("isAnonymous()")
    String guests() {
        return "guests";
    }

    @GetMapping("/open/run")
    @PreAuthorize("anonymous or hasRole('ADMIN')")
    String open() {
        return "open";
    }

    @GetMapping("/scoped/run")
    String scoped() {
        return "scoped";
    }

    @GetMapping("/team/run")
    String team() {
        return "team";
    }

    @GetMapping("/hierarchical/run")
    String hierarchical() {
        return "hierarchical";
    }

    @GetMapping("/flat/run")
    String flat() {
        return "flat";
    }
}
