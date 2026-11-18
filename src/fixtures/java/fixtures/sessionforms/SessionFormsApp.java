package fixtures.sessionforms;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The shapes a chain's repository comes in: from a helper, a delegating list, a field, a choice made at startup.
 */
@Configuration
@EnableWebSecurity
class SessionFormsSecurityConfig {

    private final SecurityContextRepository shared = new HttpSessionSecurityContextRepository();

    @Bean
    @Order(1)
    SecurityFilterChain helper(HttpSecurity http) throws Exception {
        http.securityMatcher("/helper/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())
                .securityContext(context -> context.securityContextRepository(perRequest()));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain listed(HttpSecurity http) throws Exception {
        http.securityMatcher("/listed/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())
                .securityContext(context -> context.securityContextRepository(new DelegatingSecurityContextRepository(
                        List.of(new RequestAttributeSecurityContextRepository(),
                                new HttpSessionSecurityContextRepository()))));
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain field(HttpSecurity http) throws Exception {
        http.securityMatcher("/field/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())
                .securityContext(context -> context.securityContextRepository(shared));
        return http.build();
    }

    @Bean
    @Order(4)
    SecurityFilterChain chosen(HttpSecurity http) throws Exception {
        SecurityContextRepository repository = Boolean.getBoolean("sessions")
                ? new HttpSessionSecurityContextRepository() : new RequestAttributeSecurityContextRepository();
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .httpBasic(basic -> basic.securityContextRepository(repository));
        return http.build();
    }

    private static SecurityContextRepository perRequest() {
        return new RequestAttributeSecurityContextRepository();
    }
}

@RestController
class SessionFormsController {

    @GetMapping("/helper/inbox")
    String helper() {
        return "helper";
    }
}
