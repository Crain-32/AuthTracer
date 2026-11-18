package fixtures.webfilterforms;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * HTTP-17 on WebFlux: a chain's WebFilter at {@code LAST}, and a WebFilter component whose code is in its abstract
 * base class.
 */
@SpringBootApplication
class WebFilterFormsApp {
}

@Configuration
@EnableWebFluxSecurity
class FormsChain {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .addFilterAt(new LastWebFilter(), SecurityWebFiltersOrder.LAST)
                .build();
    }
}

class LastWebFilter implements WebFilter {

    private final WebClient client = WebClient.create("http://calls:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return client.post().uri("/last").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

abstract class StampingWebFilter implements WebFilter {

    private final WebClient client = WebClient.create("http://calls:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return client.post().uri("/stamps").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

@Component
class StampWebFilter extends StampingWebFilter {
}

@RestController
class ThingsController {

    @GetMapping("/things")
    Mono<String> things() {
        return Mono.just("things");
    }
}
