package fixtures.functionalpredicates;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.POST;
import static org.springframework.web.reactive.function.server.RequestPredicates.accept;
import static org.springframework.web.reactive.function.server.RequestPredicates.method;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.resources;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.HandlerFilterFunction;
import org.springframework.web.reactive.function.server.HandlerFunction;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * WebFlux functional endpoints in the forms Spring's reference documentation shows: predicates combined with
 * {@code and(..)}, {@code method(..)} and {@code accept(..)} predicates, a builder nested by media type with routes of
 * every path under its prefix, routes a helper builds for the path it is given (in a nested builder too), filters,
 * and static resources.
 */
@Configuration
@EnableWebFluxSecurity
class FunctionalPredicatesApp {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/admin/**").hasRole("ADMIN")
                .anyExchange().authenticated()).build();
    }

    @Bean
    RouterFunction<ServerResponse> orders(OrderHandler orders) {
        return route(GET("/orders").and(accept(MediaType.APPLICATION_JSON)), orders::list)
                .andRoute(path("/orders/{id}").and(method(HttpMethod.PUT)), orders::update)
                .andNest(path("/admin/orders"), route(method(HttpMethod.DELETE), orders::purge))
                .andNest(accept(MediaType.TEXT_PLAIN), route(GET("/orders/export"), orders::export))
                .filter(new AuditFilter());
    }

    @Bean
    RouterFunction<ServerResponse> people(PersonHandler handler) {
        return route()
                .path("/person", builder -> builder
                        .nest(accept(MediaType.APPLICATION_JSON), nested -> nested
                                .GET("/{id}", handler::getPerson)
                                .GET(handler::listPeople))
                        .POST(handler::createPerson))
                .route(POST("/people/import"), handler::importPeople)
                .add(nest(accept(MediaType.APPLICATION_JSON), route(GET("/people/count"), handler::count)))
                .GET("/people/search", accept(MediaType.APPLICATION_JSON), handler::search)
                .before(request -> request)
                .build();
    }

    @Bean
    RouterFunction<ServerResponse> invoices(InvoiceHandler invoices) {
        return crud("/invoices", invoices);
    }

    private static RouterFunction<ServerResponse> crud(String path, InvoiceHandler handler) {
        return route().GET(path, handler::list).POST(path, handler::create).build();
    }

    @Bean
    RouterFunction<ServerResponse> reports(ReportHandler reports) {
        return versioned("/v2", reports);
    }

    private static RouterFunction<ServerResponse> versioned(String version, ReportHandler handler) {
        return route().path("/reports", builder -> builder.GET(version, handler::latest)).build();
    }

    @Bean
    RouterFunction<ServerResponse> assets() {
        return resources("/assets/**", new ClassPathResource("static/"));
    }
}

record Order(long id, String customer) {
}

record Person(String name, String email) {
}

record Invoice(long id, String number) {
}

class AuditFilter implements HandlerFilterFunction<ServerResponse, ServerResponse> {

    @Override
    public Mono<ServerResponse> filter(ServerRequest request, HandlerFunction<ServerResponse> next) {
        return next.handle(request);
    }
}

@Component
class OrderHandler {

    Mono<ServerResponse> list(ServerRequest request) {
        return ServerResponse.ok().body(Flux.just(new Order(1, "ann")), Order.class);
    }

    Mono<ServerResponse> update(ServerRequest request) {
        return ServerResponse.ok().bodyValue(new Order(1, "ann"));
    }

    Mono<ServerResponse> purge(ServerRequest request) {
        return ServerResponse.noContent().build();
    }

    Mono<ServerResponse> export(ServerRequest request) {
        return ServerResponse.ok().body(Flux.just(new Order(1, "ann")),
                new ParameterizedTypeReference<Order>() {
                });
    }
}

@Component
class PersonHandler {

    Mono<ServerResponse> getPerson(ServerRequest request) {
        return ServerResponse.ok().bodyValue(new Person("ann", "ann@example.com"));
    }

    Mono<ServerResponse> listPeople(ServerRequest request) {
        return ServerResponse.ok().bodyValue(List.of(new Person("ann", "ann@example.com")));
    }

    Mono<ServerResponse> createPerson(ServerRequest request) {
        return ServerResponse.ok().build();
    }

    Mono<ServerResponse> importPeople(ServerRequest request) {
        return ServerResponse.accepted().build();
    }

    Mono<ServerResponse> count(ServerRequest request) {
        return ServerResponse.ok().bodyValue(1L);
    }

    Mono<ServerResponse> search(ServerRequest request) {
        return ServerResponse.ok().build();
    }
}

@Component
class InvoiceHandler {

    Mono<ServerResponse> list(ServerRequest request) {
        return ServerResponse.ok().bodyValue(new Invoice(1, "INV-1"));
    }

    Mono<ServerResponse> create(ServerRequest request) {
        return ServerResponse.ok().build();
    }
}

@Component
class ReportHandler {

    Mono<ServerResponse> latest(ServerRequest request) {
        return ServerResponse.ok().build();
    }
}
