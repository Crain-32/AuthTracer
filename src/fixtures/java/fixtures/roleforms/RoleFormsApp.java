package fixtures.roleforms;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * ROLE-01 and ROLE-02 from the environment: the hierarchy and the role prefix are properties, which AuthTracer can't
 * read, so role checks are shown as written and reported.
 */
@Configuration
@EnableWebSecurity
class RoleFormsConfig {

    @Bean
    static RoleHierarchy roleHierarchy(@Value("${security.role-hierarchy}") String hierarchy) {
        return RoleHierarchyImpl.fromHierarchy(hierarchy);
    }

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults(@Value("${security.role-prefix}") String prefix) {
        return new GrantedAuthorityDefaults(prefix);
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/staff/**").hasAllRoles("STAFF", "TRAINED")
                .anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class RoleFormsController {

    @GetMapping("/staff/rota")
    String rota() {
        return "rota";
    }
}
