package fixtures.functionalnest;

import static org.springframework.web.reactive.function.server.RequestPredicates.DELETE;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.POST;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import reactor.core.publisher.Mono;

/**
 * Static RouterFunctions.nest(..), andNest(..), and(..), and routes built in a helper method.
 */
@Configuration
@EnableWebFluxSecurity
class FunctionalNestApp {

    @Bean
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/api/admin/**").hasRole("ADMIN")
                .anyExchange().authenticated()).build();
    }

    @Bean
    RouterFunction<ServerResponse> routes(ItemHandler items) {
        return nest(path("/api"), route(GET("/items"), items::list).andRoute(POST("/items"), items::create)
                .andNest(path("/admin"), route(DELETE("/items/{id}"), items::delete)))
                .and(statusRoutes(items));
    }

    private RouterFunction<ServerResponse> statusRoutes(ItemHandler items) {
        return route(GET("/status"), items::status);
    }
}

record Item(Long id, String name) {
}

@Component
class ItemHandler {

    Mono<ServerResponse> list(ServerRequest request) {
        return ServerResponse.ok().bodyValue(new Item(1L, "item"));
    }

    Mono<ServerResponse> create(ServerRequest request) {
        return ServerResponse.ok().build();
    }

    Mono<ServerResponse> delete(ServerRequest request) {
        return ServerResponse.noContent().build();
    }

    Mono<ServerResponse> status(ServerRequest request) {
        return ServerResponse.ok().bodyValue("up");
    }
}
