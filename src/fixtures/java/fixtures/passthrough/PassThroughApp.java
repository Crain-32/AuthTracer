package fixtures.passthrough;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A chain for the internal network, matched by a RequestMatcher AuthTracer can't evaluate, ahead of a webhooks chain
 * that authorizes nothing (the webhooks check their own signatures) and an API chain. Requests none of them is sure
 * to cover may still be taken by the internal one.
 */
@Configuration
@EnableWebSecurity
class PassThroughConfig {

    @Bean
    @Order(1)
    SecurityFilterChain internal(HttpSecurity http) throws Exception {
        http.securityMatcher(request -> request.getRemoteAddr().startsWith("10."))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("INTERNAL"));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain webhooks(HttpSecurity http) throws Exception {
        http.securityMatcher("/webhooks/**")
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@RestController
class PassThroughController {

    @PostMapping("/webhooks/github")
    void github() {
    }

    @GetMapping("/api/orders")
    String orders() {
        return "orders";
    }

    @GetMapping("/status")
    String status() {
        return "up";
    }
}
