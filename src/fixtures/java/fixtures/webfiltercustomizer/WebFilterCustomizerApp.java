package fixtures.webfiltercustomizer;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Decision 0070 (amended) on WebFlux: a {@code Customizer<ServerHttpSecurity>} bean adds a WebFilter to the chain.
 */
@SpringBootApplication
@EnableWebFluxSecurity
class WebFilterCustomizerApp {

    @Bean
    Customizer<ServerHttpSecurity> tenants() {
        return http -> http.addFilterAt(new TenantWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION);
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .httpBasic(Customizer.withDefaults()).build();
    }
}

class TenantWebFilter implements WebFilter {

    private final WebClient tenants = WebClient.create("http://tenants:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return tenants.get().uri("/tenants/current").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

@RestController
class ItemsController {

    @GetMapping("/items")
    Mono<String> items() {
        return Mono.just("items");
    }
}
