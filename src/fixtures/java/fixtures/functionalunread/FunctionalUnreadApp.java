package fixtures.functionalunread;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.POST;
import static org.springframework.web.reactive.function.server.RequestPredicates.accept;
import static org.springframework.web.reactive.function.server.RequestPredicates.methods;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.RequestPredicate;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import reactor.core.publisher.Mono;

/**
 * Decision 0080: routes AuthTracer reads only in part. Predicates combined with or(..) and methods(..); a lambda
 * predicate that narrows a known route; a custom RequestPredicate and a negated one, which say nothing AuthTracer can
 * read about the path; HandlerFunction classes as handlers (a bean, a new instance); a handler looked up at runtime;
 * routes held in a field; a bean that is a RouterFunction class of its own; another RouterFunction bean nested under a
 * prefix; a HandlerFunction bean injected by its interface where there are two; and a predicate constant, which it
 * reads.
 */
@Configuration
@EnableWebFluxSecurity
class FunctionalUnreadApp {

    private static final RequestPredicate JSON = accept(MediaType.APPLICATION_JSON);

    private final RouterFunction<ServerResponse> pluginRoutes;

    FunctionalUnreadApp(PluginRoutes plugins) {
        this.pluginRoutes = plugins.routes();
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/admin/**").hasRole("ADMIN")
                .pathMatchers("/export").hasRole("AUDITOR").anyExchange().authenticated()).build();
    }

    @Bean
    RouterFunction<ServerResponse> orders(OrderHandler orders, ExportFunction export,
            Map<String, HandlerFunction<ServerResponse>> hooks) {
        return route(GET("/orders").or(GET("/purchases")), orders::list)
                .andRoute(POST("/orders").and(request -> request.headers().header("X-Tenant").size() == 1),
                        orders::create)
                .andRoute(methods(HttpMethod.PUT, HttpMethod.PATCH).and(path("/orders/{id}")), orders::update)
                .andRoute(new TenantPredicate(), orders::tenant)
                .andRoute(path("/admin/**").negate(), orders::fallback)
                .andRoute(GET("/export"), export)
                .andRoute(GET("/admin/audit"), new AuditFunction())
                .andRoute(GET("/hooks/{name}"), hooks.get("default"))
                .andRoute(GET("/catalog").and(JSON), orders::list)
                .and(pluginRoutes);
    }

    @Bean
    RouterFunction<ServerResponse> reports(OrderHandler orders) {
        return route()
                .GET("/reports", request -> request.queryParam("year").isPresent(), orders::list)
                .route(request -> request.path().startsWith("/admin/reports"), orders::purge)
                .build();
    }

    @Bean
    RouterFunction<ServerResponse> plugins() {
        return new PluginRouter();
    }

    @Bean
    RouterFunction<ServerResponse> api(RouterFunction<ServerResponse> reports) {
        return nest(path("/api"), reports);
    }

    @Bean
    RouterFunction<ServerResponse> audits(HandlerFunction<ServerResponse> auditFunction) {
        return route(GET("/audits"), auditFunction);
    }
}

record Order(long id, String customer) {
}

class TenantPredicate implements RequestPredicate {

    @Override
    public boolean test(ServerRequest request) {
        return request.headers().header("X-Tenant").contains("acme");
    }
}

@Component
class ExportFunction implements HandlerFunction<ServerResponse> {

    @Override
    public Mono<ServerResponse> handle(ServerRequest request) {
        return ServerResponse.ok().bodyValue(new Order(1, "ann"));
    }
}

@Component
class AuditFunction implements HandlerFunction<ServerResponse> {

    @Override
    public Mono<ServerResponse> handle(ServerRequest request) {
        return ServerResponse.ok().build();
    }
}

@Component
class PluginRoutes {

    RouterFunction<ServerResponse> routes() {
        return route(GET("/plugins/status"), request -> ServerResponse.ok().build());
    }
}

class PluginRouter implements RouterFunction<ServerResponse> {

    @Override
    public Mono<HandlerFunction<ServerResponse>> route(ServerRequest request) {
        return Mono.empty();
    }
}

@Component
class OrderHandler {

    Mono<ServerResponse> list(ServerRequest request) {
        return ServerResponse.ok().bodyValue(new Order(1, "ann"));
    }

    Mono<ServerResponse> create(ServerRequest request) {
        return ServerResponse.ok().build();
    }

    Mono<ServerResponse> update(ServerRequest request) {
        return ServerResponse.ok().build();
    }

    Mono<ServerResponse> tenant(ServerRequest request) {
        return ServerResponse.ok().build();
    }

    Mono<ServerResponse> fallback(ServerRequest request) {
        return ServerResponse.notFound().build();
    }

    Mono<ServerResponse> purge(ServerRequest request) {
        return ServerResponse.noContent().build();
    }
}
