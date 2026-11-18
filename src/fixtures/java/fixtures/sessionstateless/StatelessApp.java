package fixtures.sessionstateless;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A stateless API that still takes a form login, Basic, a remember-me cookie, a one-time token or a container user:
 * nothing outlives the request, so each request that signs in looks the user up again.
 */
@Configuration
@EnableWebSecurity
class StatelessSecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())
                .httpBasic(withDefaults())
                .rememberMe(remember -> remember.key("fixture"))
                .oneTimeTokenLogin(withDefaults())
                .jee(jee -> jee.mappableRoles("USER"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}

@RestController
class StatelessController {

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
