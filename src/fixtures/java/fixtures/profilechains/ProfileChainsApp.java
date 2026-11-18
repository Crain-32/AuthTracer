package fixtures.profilechains;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0111: beans that depend on the active profiles and on properties. The configuration activates dev
 * (application.properties); a deployment may activate prod, or secure, as well.
 */
@Configuration
@EnableWebSecurity
class ProfileChainsConfig {

    /**
     * Only with prod: the admin pages need an admin.
     */
    @Bean
    @Order(1)
    @Profile("prod")
    SecurityFilterChain prod(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**").authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("ADMIN"));
        return http.build();
    }

    /**
     * With dev, which the configuration activates: anyone signed in.
     */
    @Bean
    @Order(2)
    @Profile("dev")
    SecurityFilterChain dev(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**").authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    @Order(3)
    @Profile("!test")
    SecurityFilterChain rest(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
        return http.build();
    }
}

/**
 * Method security only with the secure profile, which the configuration doesn't activate.
 */
@Configuration
@Profile("secure")
@EnableMethodSecurity
class SecureMethodsConfig {
}

@RestController
class ProfileChainsController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}

/**
 * Only when app.debug.enabled is true, which the configuration doesn't set.
 */
@RestController
@ConditionalOnProperty(name = "app.debug.enabled", havingValue = "true")
class DebugController {

    @GetMapping("/debug/state")
    String state() {
        return "state";
    }
}

/**
 * The configuration sets app.ping.enabled: a bean.
 */
@RestController
@ConditionalOnProperty(prefix = "app.ping", name = "enabled")
class PingController {

    @GetMapping("/ping")
    String ping() {
        return "pong";
    }
}
