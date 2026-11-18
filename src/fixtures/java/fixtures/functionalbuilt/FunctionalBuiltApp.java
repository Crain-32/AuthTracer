package fixtures.functionalbuilt;

import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import reactor.core.publisher.Mono;

/**
 * Routes a builder builds take the prefix of wherever the RouterFunction goes: a static nest(..), a builder's
 * nest(..) supplier, or a builder's path(..) consumer.
 */
@Configuration
class FunctionalBuiltApp {

    @Bean
    RouterFunction<ServerResponse> v1(ItemHandler items) {
        return nest(path("/v1"), route().GET("/items", items::list).build());
    }

    @Bean
    RouterFunction<ServerResponse> v2(ItemHandler items) {
        return route()
                .nest(path("/v2"), () -> route().GET("/items", items::list).build())
                .path("/admin", admin -> admin.DELETE("/items/{id}", items::delete))
                .build();
    }
}

@Component
class ItemHandler {

    Mono<ServerResponse> list(ServerRequest request) {
        return ServerResponse.ok().build();
    }

    Mono<ServerResponse> delete(ServerRequest request) {
        return ServerResponse.noContent().build();
    }
}
