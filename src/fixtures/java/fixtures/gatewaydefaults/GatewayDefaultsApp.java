package fixtures.gatewaydefaults;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The WebFlux gateway's default filters (application.yml) apply to the routes in the properties: they strip the
 * first segment and drop the caller's Authorization header, which a route's TokenRelay puts back. A route a
 * RouteLocator bean builds gets none of them.
 */
@Configuration
class GatewayDefaultsConfig {

    @Bean
    RouteLocator built(RouteLocatorBuilder builder) {
        return builder.routes().route("built", route -> route.path("/api/built/**").uri("http://built:8083"))
                .build();
    }
}
