package fixtures.webfluxdefault;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * No SecurityWebFilterChain bean: @EnableWebFluxSecurity's own chain, after the customizer's rule.
 */
@Configuration
@EnableWebFluxSecurity
class DefaultApp {

    @Bean
    Customizer<ServerHttpSecurity> docs() {
        return http -> http.authorizeExchange(exchange -> exchange.pathMatchers("/docs/**").permitAll());
    }
}

@RestController
class DefaultController {

    @GetMapping("/docs/index")
    Mono<String> docs() {
        return Mono.just("docs");
    }

    @GetMapping("/data")
    Mono<String> data() {
        return Mono.just("data");
    }
}
