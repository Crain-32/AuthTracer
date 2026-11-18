package fixtures.webfilters;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
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
 * HTTP-17 on WebFlux: a chain's WebFilters around its AUTHORIZATION filter, and WebFilter beans around
 * WebFilterChainProxy (-100).
 */
@SpringBootApplication
class WebFiltersApp {
}

@Configuration
@EnableWebFluxSecurity
class WebFilterChains {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .httpBasic(Customizer.withDefaults())
                .addFilterAt(new TenantWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterAfter(new QuotaWebFilter(), SecurityWebFiltersOrder.AUTHORIZATION)
                // FIRST is Integer.MIN_VALUE: one before it wraps around to Integer.MAX_VALUE, the last.
                .addFilterBefore(new WrappedWebFilter(), SecurityWebFiltersOrder.FIRST)
                .build();
    }

    /**
     * No order: the lowest precedence, after Spring Security's.
     */
    @Bean
    WebFilter metrics() {
        return new MetricsWebFilter();
    }
}

@Component
@Order(-200)
class TraceWebFilter implements WebFilter {

    private final WebClient traces = WebClient.create("http://traces:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return traces.post().uri("/spans").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

class TenantWebFilter implements WebFilter {

    private final WebClient tenants = WebClient.create("http://tenants:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return tenants.get().uri("/tenants/current").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

class QuotaWebFilter implements WebFilter {

    private final WebClient quotas = WebClient.create("http://quotas:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return quotas.post().uri("/quotas/use").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

class WrappedWebFilter implements WebFilter {

    private final WebClient wrapped = WebClient.create("http://wrapped:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return wrapped.post().uri("/wrapped").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

class MetricsWebFilter implements WebFilter {

    private final WebClient metrics = WebClient.create("http://metrics:8080");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return metrics.post().uri("/hits").retrieve().toBodilessEntity().then(chain.filter(exchange));
    }
}

@RestController
class ItemsController {

    @GetMapping("/items")
    Mono<String> items() {
        return Mono.just("items");
    }
}
