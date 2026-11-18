package fixtures.functional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class FunctionalApp {

    @Bean
    RouterFunction<ServerResponse> routes(BookHandler books) {
        return RouterFunctions.route()
                .GET("/books/{id}", books::get)
                .POST("/books", books::create)
                .path("/admin", builder -> builder.DELETE("/books/{id}", books::delete))
                .nest(RequestPredicates.path("/shelves"), builder -> builder.GET("", books::shelves))
                .build();
    }

    @Bean
    RouterFunction<ServerResponse> legacy(BookHandler books) {
        return RouterFunctions.route(RequestPredicates.GET("/legacy/books"), books::shelves)
                .andRoute(RequestPredicates.POST("/legacy/books"), request -> books.create(request));
    }

    @Bean
    SecurityWebFilterChain app(ServerHttpSecurity http) {
        return http.authorizeExchange(exchange -> exchange
                .pathMatchers("/admin/**").hasRole("ADMIN")
                .anyExchange().authenticated()).build();
    }
}

record Book(long id, String title, String isbn) {
}

record BookView(String title, String isbn) {

    static BookView of(Book book) {
        return new BookView(book.title(), book.isbn());
    }
}

@Service
class Catalog {

    @PreAuthorize("hasRole('READER')")
    Mono<Book> find(long id) {
        return Mono.just(new Book(id, "Dune", "978"));
    }

    Flux<Book> all() {
        return Flux.just(new Book(1, "Dune", "978"));
    }
}

@Component
class BookHandler {

    private final Catalog catalog;

    BookHandler(Catalog catalog) {
        this.catalog = catalog;
    }

    Mono<ServerResponse> get(ServerRequest request) {
        return catalog.find(Long.parseLong(request.pathVariable("id")))
                .flatMap(book -> ServerResponse.ok().bodyValue(BookView.of(book)));
    }

    Mono<ServerResponse> create(ServerRequest request) {
        return ServerResponse.ok().build();
    }

    Mono<ServerResponse> delete(ServerRequest request) {
        return ServerResponse.noContent().build();
    }

    Mono<ServerResponse> shelves(ServerRequest request) {
        return ServerResponse.ok().body(catalog.all().map(BookView::of), BookView.class);
    }
}
