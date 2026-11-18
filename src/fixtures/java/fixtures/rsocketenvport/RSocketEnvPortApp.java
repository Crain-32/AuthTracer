package fixtures.rsocketenvport;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Mono;

/**
 * Decision 0045: an RSocket server on a port the environment sets ({@code ${RSOCKET_PORT}}). Over WebSocket on a
 * port of its own, it runs beside the WebFlux server, not behind it, so the HTTP rule for its mapping path doesn't
 * apply.
 */
@SpringBootApplication
class RSocketEnvPortApp {

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/rsocket").denyAll()
                .anyExchange().authenticated()).build();
    }
}

@Controller
@MessageMapping("quotes")
class QuoteController {

    @MessageMapping
    Mono<String> all() {
        return Mono.just("all");
    }

    @MessageMapping("latest")
    Mono<String> latest() {
        return Mono.just("latest");
    }
}

/**
 * A class-level mapping with no route adds none.
 */
@Controller
@MessageMapping
class PingController {

    @MessageMapping("ping")
    Mono<String> ping() {
        return Mono.just("pong");
    }
}
