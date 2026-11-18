package fixtures.gateway;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * A Spring Cloud Gateway: routes in application.yml and in a RouteLocator bean, behind the gateway's own rules.
 */
@Configuration
@EnableWebFluxSecurity
class GatewayConfig {

    @Bean
    RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("teams", route -> route.path("/api/teams/**").and().method(HttpMethod.GET, HttpMethod.POST)
                        .filters(filter -> filter.stripPrefix(1).tokenRelay())
                        .uri("http://localhost:8083"))
                .build();
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        http.authorizeExchange(exchanges -> exchanges.pathMatchers("/admin/**").hasRole("ADMIN")
                .pathMatchers("/api/teams/public/**").permitAll()
                .anyExchange().authenticated());
        return http.build();
    }
}
