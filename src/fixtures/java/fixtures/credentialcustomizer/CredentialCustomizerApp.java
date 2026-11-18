package fixtures.credentialcustomizer;

import org.springframework.boot.restclient.RestClientCustomizer;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * A RestClientCustomizer written as a component class: its credentials are on every client built from Boot's
 * builder, here one an abstract base class makes calls with.
 */
@Component
class PartnerCustomizer implements RestClientCustomizer {

    @Override
    public void customize(RestClient.Builder builder) {
        builder.defaultHeaders(headers -> headers.setBasicAuth("partner", "secret"));
    }
}

abstract class CatalogCalls {

    private final RestClient client;

    CatalogCalls(RestClient.Builder builder) {
        this.client = builder.baseUrl("http://catalog:8080").build();
    }

    abstract String section();

    String list() {
        return client.get().uri("/catalog/{section}", section()).retrieve().body(String.class);
    }
}

@Component
class BookCalls extends CatalogCalls {

    BookCalls(RestClient.Builder builder) {
        super(builder);
    }

    @Override
    String section() {
        return "books";
    }
}

@RestController
class CatalogController {

    private final BookCalls books;

    CatalogController(BookCalls books) {
        this.books = books;
    }

    @GetMapping("/books")
    String books() {
        return books.list();
    }
}
