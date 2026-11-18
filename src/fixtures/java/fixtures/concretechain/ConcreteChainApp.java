package fixtures.concretechain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The chain bean declares the concrete type HttpSecurity.build() returns.
 */
@Configuration
class ConcreteChainConfig {

    @Bean
    DefaultSecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll());
        return http.build();
    }
}

@RestController
class ConcreteChainController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/open")
    String open() {
        return "open";
    }
}
