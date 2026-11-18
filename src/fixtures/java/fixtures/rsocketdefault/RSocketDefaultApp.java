package fixtures.rsocketdefault;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Mono;

/**
 * RX-13: RSocket over the WebFlux server's WebSocket at /rsocket, with Spring Security's default RSocket rules.
 */
@SpringBootApplication
class RSocketDefaultApp {

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/rsocket").permitAll()
                .anyExchange().authenticated()).build();
    }
}

@Controller
class HelloController {

    @MessageMapping("hello")
    Mono<String> hello(String name) {
        return Mono.just("Hello " + name);
    }
}
