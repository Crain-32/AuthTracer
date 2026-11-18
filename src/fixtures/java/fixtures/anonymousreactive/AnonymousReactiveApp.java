package fixtures.anonymousreactive;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * WebFlux doesn't authenticate callers anonymously unless asked to, so no caller who hasn't signed in has the
 * anonymous role.
 */
@Configuration
@EnableWebFluxSecurity
class AnonymousReactiveConfig {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchange -> exchange
                        .pathMatchers("/welcome").hasAnyRole("ANONYMOUS", "USER")
                        .anyExchange().authenticated())
                .build();
    }
}

@RestController
class WelcomeController {

    @GetMapping("/welcome")
    String welcome() {
        return "welcome";
    }
}
