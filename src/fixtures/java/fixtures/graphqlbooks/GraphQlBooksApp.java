package fixtures.graphqlbooks;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;

import graphql.schema.DataFetchingEnvironment;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.BatchMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Decision 0029: a reactive bookstore, shaped like Spring for GraphQL's samples: resolvers returning Mono and List, a
 * primitive, a value read through the DataFetchingEnvironment, a batch returning Mono of a Map, and a resolver that
 * calls the inventory service.
 */
@Configuration
@EnableMethodSecurity
class GraphQlBooksApp {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/graphql").authenticated()
                .anyRequest().denyAll());
        return http.build();
    }
}

record Book(String id, String title, String authorId) {
}

record Author(String id, String name) {
}

record Review(String text, int stars) {
}

record Price(String currency, BigDecimal amount) {
}

record Publisher(String name) {
}

@Service
class Reviews {

    @PreAuthorize("hasRole('REVIEWER')")
    public List<Review> of(String bookId) {
        return List.of(new Review("good", 5));
    }
}

@Service
class Inventory {

    private final RestClient client;

    Inventory(RestClient.Builder builder) {
        this.client = builder.baseUrl("http://inventory:8085").build();
    }

    int stock(String bookId) {
        return client.get().uri("/stock/{id}", bookId).retrieve().body(Integer.class);
    }
}

@Controller
class BookController {

    private final Reviews reviews;
    private final Inventory inventory;

    BookController(Reviews reviews, Inventory inventory) {
        this.reviews = reviews;
        this.inventory = inventory;
    }

    @QueryMapping
    Mono<Book> bookById(@Argument String id) {
        return Mono.just(new Book(id, "Dune", "1"));
    }

    @QueryMapping
    Flux<Book> books() {
        return Flux.just(new Book("1", "Dune", "1"));
    }

    @SchemaMapping
    Mono<Author> author(Book book) {
        return Mono.just(new Author(book.authorId(), "Herbert"));
    }

    /**
     * Two checks every way through: the resolver's own and the service's.
     */
    @SchemaMapping
    @PreAuthorize("hasRole('MEMBER')")
    List<Review> reviews(Book book) {
        return reviews.of(book.id());
    }

    @SchemaMapping
    int stock(Book book) {
        return inventory.stock(book.id());
    }

    /**
     * The source isn't a parameter: the type is named, and is the application's Book.
     */
    @SchemaMapping(typeName = "Book", field = "price")
    Price price(DataFetchingEnvironment environment) {
        Book book = environment.getSource();
        return new Price("EUR", BigDecimal.TEN);
    }

    @BatchMapping
    Mono<Map<Book, Publisher>> publisher(Set<Book> books) {
        return Mono.just(Map.of());
    }

    /**
     * A type the application has no class for, and a field of no type at all: not resolvers AuthTracer can place.
     */
    @SchemaMapping(typeName = "Shelf", field = "label")
    String label(DataFetchingEnvironment environment) {
        return "A";
    }

    @SchemaMapping
    String summary(DataFetchingEnvironment environment) {
        return "summary";
    }
}
