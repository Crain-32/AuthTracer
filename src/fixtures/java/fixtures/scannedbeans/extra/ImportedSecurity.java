package fixtures.scannedbeans.extra;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Outside the component scan, but the application imports it: a bean.
 */
@Configuration
public class ImportedSecurity {

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/legacy/**").hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();
    }
}

/**
 * Outside the component scan, and nothing imports it: its endpoints may not exist.
 */
@RestController
class LegacyController {

    @GetMapping("/legacy/items")
    String items() {
        return "legacy";
    }
}

/**
 * Outside the component scan: its hierarchy may not apply.
 */
@Configuration
class StrayRoles {

    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
    }
}
