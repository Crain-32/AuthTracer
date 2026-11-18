package fixtures.sessionreactive;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * WebFlux: a chain that keeps no context, and one whose Basic saves to the session.
 */
@Configuration
@EnableWebFluxSecurity
class SessionReactiveSecurityConfig {

    @Bean
    @Order(1)
    SecurityWebFilterChain api(ServerHttpSecurity http) {
        return http.securityMatcher(ServerWebExchangeMatchers.pathMatchers("/api/**"))
                .authorizeExchange(exchange -> exchange.anyExchange().authenticated())
                .formLogin(withDefaults())
                .httpBasic(withDefaults())
                .oneTimeTokenLogin(withDefaults())
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .build();
    }

    @Bean
    @Order(2)
    SecurityWebFilterChain app(ServerHttpSecurity http) {
        return http.authorizeExchange(exchange -> exchange.anyExchange().authenticated())
                .httpBasic(basic -> basic.securityContextRepository(new WebSessionServerSecurityContextRepository()))
                .build();
    }
}

@RestController
class SessionReactiveController {

    @GetMapping("/api/inbox")
    Mono<String> inbox() {
        return Mono.just("inbox");
    }
}
