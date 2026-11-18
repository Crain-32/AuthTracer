package fixtures.functionalmvcunread;

import static org.springframework.web.servlet.function.RequestPredicates.DELETE;
import static org.springframework.web.servlet.function.RequestPredicates.GET;
import static org.springframework.web.servlet.function.RequestPredicates.method;
import static org.springframework.web.servlet.function.RequestPredicates.path;
import static org.springframework.web.servlet.function.RouterFunctions.route;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.function.HandlerFunction;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Decision 0080: Spring MVC functional endpoints AuthTracer reads only in part. A HandlerFunction bean injected by
 * its interface (the only one), whose checks are on the path; an or(..) of two paths nested under a prefix; a route
 * nested under a lambda predicate; a path and a method that aren't constants; a handler looked up at runtime.
 */
@Configuration
@EnableMethodSecurity
class FunctionalMvcUnreadApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()).build();
    }

    @Bean
    RouterFunction<ServerResponse> items(HandlerFunction<ServerResponse> items, ItemService service,
            Map<String, HandlerFunction<ServerResponse>> legacy) {
        return route()
                .path("/api", api -> api
                        .GET("/items", items)
                        .route(GET("/stock").or(GET("/inventory")), request -> ServerResponse.ok().body(
                                service.stock())))
                .nest(request -> request.param("beta").isPresent(), beta -> beta
                        .DELETE("/api/admin/items/{id}", request -> ServerResponse.noContent().build()))
                .add(route(DELETE(service.prefix() + "/items"), request -> ServerResponse.ok().build()))
                .add(route(path("/health"), request -> ServerResponse.ok().build()))
                .add(route(method(HttpMethod.valueOf(service.verb())).and(path("/verbs")),
                        request -> ServerResponse.ok().build()))
                .GET("/legacy", legacy.get("legacy"))
                .build();
    }
}

record Item(long id, String name) {
}

@Component
class ItemsFunction implements HandlerFunction<ServerResponse> {

    private final ItemService service;

    ItemsFunction(ItemService service) {
        this.service = service;
    }

    @Override
    public ServerResponse handle(ServerRequest request) {
        return ServerResponse.ok().body(service.list());
    }
}

@Service
class ItemService {

    @PreAuthorize("hasRole('CLERK')")
    Item list() {
        return new Item(1, "pen");
    }

    long stock() {
        return 3;
    }

    String prefix() {
        return "/api/v2";
    }

    String verb() {
        return "PUT";
    }
}
