package fixtures.gatewaymvcforms;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.prefixPath;
import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.setPath;
import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;
import static org.springframework.web.servlet.function.RequestPredicates.accept;
import static org.springframework.web.servlet.function.RequestPredicates.path;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Decision 0043: Server MVC routes, two in one bean: one with a path filter, and one with no id, request predicates
 * rather than a method (one that isn't on the path), and a URI from a property.
 */
@Configuration
class GatewayMvcFormsConfig {

    @Bean
    RouterFunction<ServerResponse> catalog(@Value("${legacy.uri}") String legacyUri) {
        return route("products").GET("/products/**", http()).before(uri("http://localhost:8091"))
                .before(prefixPath("/api")).build()
                .and(route().route(path("/legacy/**").and(accept(MediaType.APPLICATION_XML)), http())
                        .before(uri(legacyUri)).before(setPath("/v1/legacy")).build());
    }
}
