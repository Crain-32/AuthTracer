package fixtures.webstacknoboot;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import reactor.core.publisher.Mono;

/**
 * Decision 0079: without Spring Boot (the test leaves its jars out), how the application is started decides the
 * stack; its security configuration is the evidence there is.
 */
@Configuration
@EnableWebFlux
@EnableWebFluxSecurity
class WebStackNoBootConfig {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().hasRole("STAFF")).build();
    }
}

@RestController
class ReportController {

    @GetMapping("/reports")
    Mono<String> reports() {
        return Mono.just("reports");
    }
}
