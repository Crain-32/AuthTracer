package fixtures.gatewaymvcconfig;

import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;
import static org.springframework.web.servlet.function.RequestPredicates.GET;
import static org.springframework.web.servlet.function.RequestPredicates.accept;
import static org.springframework.web.servlet.function.RequestPredicates.method;
import static org.springframework.web.servlet.function.RequestPredicates.path;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.server.mvc.filter.FilterFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Decision 0043: Server MVC routes made with the static {@code route(predicate, handler)}: a path from a property's
 * URI, a method and path joined with another predicate, and a method joined with a path, after a route of the
 * builder's.
 */
@Configuration
class GatewayMvcConfigConfig {

    @Bean
    RouterFunction<ServerResponse> routes(@Value("${routes.orders-uri}") String ordersUri) {
        return route("catalog").GET("/catalog/**", http()).build()
                .and(route(path("/orders/**"), http()).filter(FilterFunctions.uri(ordersUri)))
                .and(route(GET("/stock/{sku}").and(accept(MediaType.APPLICATION_JSON)), http())
                        .filter(FilterFunctions.uri("http://stock:8080")))
                .and(route(method(HttpMethod.POST).and(path("/payments")), http())
                        .filter(FilterFunctions.uri("http://payments:8080")));
    }
}
