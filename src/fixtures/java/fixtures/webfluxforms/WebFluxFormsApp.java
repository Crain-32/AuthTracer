package fixtures.webfluxforms;

import org.springframework.boot.security.autoconfigure.web.reactive.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * RX-01 and RX-03 in the shapes WebFlux configurations take: a chain for GET requests to /internal/** from the
 * office network, and one for every exchange with CORS preflight, Boot's static resources and a login page of its
 * own.
 */
@Configuration
@EnableWebFluxSecurity
class WebFluxFormsConfig {

    @Bean
    @Order(1)
    SecurityWebFilterChain internal(ServerHttpSecurity http) {
        return http.securityMatcher(new PathPatternParserServerWebExchangeMatcher("/internal/**", HttpMethod.GET))
                .authorizeExchange(exchange -> exchange.anyExchange().hasIpAddress("10.0.0.0/8"))
                .build();
    }

    @Bean
    @Order(2)
    SecurityWebFilterChain app(ServerHttpSecurity http) {
        return http.securityMatcher(ServerWebExchangeMatchers.anyExchange())
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .matchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                        .pathMatchers("/signin").permitAll()
                        .anyExchange().authenticated())
                .formLogin(form -> form.loginPage("/signin"))
                .build();
    }
}

@RestController
class WebFluxFormsController {

    @GetMapping("/internal/stats")
    Mono<String> stats() {
        return Mono.just("stats");
    }

    @RequestMapping(path = "/internal/stats", method = RequestMethod.DELETE)
    Mono<Void> reset() {
        return Mono.empty();
    }

    @RequestMapping(path = "/orders", method = RequestMethod.OPTIONS)
    Mono<Void> preflight() {
        return Mono.empty();
    }

    @GetMapping("/orders")
    Mono<String> orders() {
        return Mono.just("orders");
    }

    @GetMapping("/css/app")
    Mono<String> stylesheet() {
        return Mono.just("body {}");
    }
}
