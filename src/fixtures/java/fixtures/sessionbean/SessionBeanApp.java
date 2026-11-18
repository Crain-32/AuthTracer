package fixtures.sessionbean;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The chain's repository is a bean: one that keeps the context for the request only.
 */
@Configuration
@EnableWebSecurity
class SessionBeanSecurityConfig {

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new RequestAttributeSecurityContextRepository();
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http, SecurityContextRepository repository) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())
                .securityContext(context -> context.securityContextRepository(repository));
        return http.build();
    }
}

@RestController
class SessionBeanController {

    @GetMapping("/inbox")
    String inbox() {
        return "inbox";
    }
}
