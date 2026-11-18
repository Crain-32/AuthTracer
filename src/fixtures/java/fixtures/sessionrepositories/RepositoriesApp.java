package fixtures.sessionrepositories;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Three chains, each keeping the SecurityContext its own way.
 */
@Configuration
@EnableWebSecurity
class RepositoriesSecurityConfig {

    /**
     * Form login into a chain whose repositories keep nothing past the request.
     */
    @Bean
    @Order(1)
    SecurityFilterChain forms(HttpSecurity http) throws Exception {
        SecurityContextRepository perRequest = new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(), new NullSecurityContextRepository());
        http.securityMatcher("/forms/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())
                .securityContext(context -> context.securityContextRepository(perRequest));
        return http.build();
    }

    /**
     * Basic that saves what it reads to the session, which the chain loads again on the next request.
     */
    @Bean
    @Order(2)
    SecurityFilterChain sessions(HttpSecurity http) throws Exception {
        http.securityMatcher("/sessions/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .httpBasic(basic -> basic.securityContextRepository(new HttpSessionSecurityContextRepository()));
        return http.build();
    }

    /**
     * Basic saving to the session, in a stateless chain that never loads it.
     */
    @Bean
    @Order(3)
    SecurityFilterChain stateless(HttpSecurity http) throws Exception {
        http.securityMatcher("/stateless/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .httpBasic(basic -> basic.securityContextRepository(new HttpSessionSecurityContextRepository()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}

@RestController
class RepositoriesController {

    @GetMapping("/forms/inbox")
    String inbox() {
        return "inbox";
    }

    @GetMapping("/sessions/inbox")
    String sessions() {
        return "sessions";
    }

    @GetMapping("/stateless/inbox")
    String stateless() {
        return "stateless";
    }
}
