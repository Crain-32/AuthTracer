package fixtures.gatewayforms;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Decision 0043, the other ways routes are written: predicates and filters with their arguments spelled out, the
 * path filters and header filters, a predicate that isn't on a path, and a route in a RouteLocator bean with no id
 * whose URI is put together at run time.
 */
@Configuration
@EnableWebFluxSecurity
class GatewayFormsConfig {

    @Bean
    RouteLocator routes(RouteLocatorBuilder builder, @Value("${teams.host}") String teamsHost) {
        return builder.routes()
                .route(route -> route.path("/teams/**").uri("http://" + teamsHost + ":8083"))
                .build();
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated());
        return http.build();
    }
}
