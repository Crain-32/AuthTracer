package fixtures.mfaadditional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHZ-08 written by hand: a DefaultAuthorizationManagerFactory whose additional authorization is a factors
 * manager asking for a one-time token, with the RoleHierarchy bean and a role prefix from the environment. A negated
 * rule negates the factors too.
 */
@Configuration
@EnableWebSecurity
class MfaAdditionalConfig {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withRolePrefix("ROLE_").role("ADMIN").implies("USER").build();
    }

    @Bean
    AuthorizationManagerFactory<Object> authorizationManagerFactory(@Value("${security.role-prefix}") String prefix) {
        DefaultAuthorizationManagerFactory<Object> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setRolePrefix(prefix);
        factory.setRoleHierarchy(roleHierarchy());
        factory.setAdditionalAuthorization(AllRequiredFactorsAuthorizationManager.builder()
                .requireFactor(RequiredFactor.withAuthority(FactorGrantedAuthority.OTT_AUTHORITY).build())
                .build());
        return factory;
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/transfers/**").not().hasRole("FROZEN")
                .requestMatchers("/users/{id}/**").hasVariable("id").equalTo(Authentication::getName)
                .requestMatchers("/reports/**").hasRole("USER")
                .requestMatchers("/approvals/**").hasAllRoles("AUDITOR", "SIGNER")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class MfaAdditionalController {

    @GetMapping("/transfers/new")
    String transfer() {
        return "transfer";
    }

    @GetMapping("/users/{id}/profile")
    String profile(@PathVariable String id) {
        return "profile";
    }

    @GetMapping("/approvals/pending")
    String pending() {
        return "pending";
    }

    @GetMapping("/reports/daily")
    String daily() {
        return "daily";
    }
}
