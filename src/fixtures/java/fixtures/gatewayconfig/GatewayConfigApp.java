package fixtures.gatewayconfig;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Decision 0043: route URIs a RouteLocator bean takes from the configuration: a {@code @Value} field the route lambda
 * reads, a {@code @Value} parameter it captures, a {@code @ConfigurationProperties} getter, and one no file sets.
 */
@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties(RoutesProperties.class)
class GatewayConfigConfig {

    @Value("${routes.orders-uri}")
    private String ordersUri;

    @Bean
    RouteLocator routes(RouteLocatorBuilder builder, @Value("${routes.billing-uri}") String billingUri,
            @Value("${routes.unset-uri}") String unsetUri, RoutesProperties routes) {
        return builder.routes()
                .route("orders", route -> route.path("/orders/**").uri(ordersUri))
                .route("billing", route -> route.path("/billing/**").filters(filter -> filter.stripPrefix(1))
                        .uri(billingUri))
                .route("stock", route -> route.path("/stock/**").uri(routes.stockUri()))
                .route("unset", route -> route.path("/unset/**").uri(unsetUri))
                .build();
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated());
        return http.build();
    }
}

@ConfigurationProperties(prefix = "routes")
record RoutesProperties(String stockUri) {
}
