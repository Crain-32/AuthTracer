package fixtures.uris;

import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;

interface TicketClient {

    @GetExchange("/tickets/{id}")
    String ticket(@PathVariable long id);
}

/**
 * An HTTP interface wired by hand, not through @ImportHttpServices.
 */
@Configuration
class UrisConfig {

    @Bean
    TicketClient ticketClient() {
        RestClient client = RestClient.create("http://tickets:5050");
        HttpServiceProxyFactory factory = HttpServiceProxyFactory.builderFor(RestClientAdapter.create(client)).build();
        return factory.createClient(TicketClient.class);
    }
}

@Component
class Ledger {

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${ledger.base-url}")
    private String ledgerUrl;

    String entry() {
        return restTemplate.getForObject(URI.create("http://ledger:7070/entries/latest"), String.class);
    }

    void remove(long id) {
        URI uri = UriComponentsBuilder.fromUriString(ledgerUrl).path("/entries/{id}").queryParam("hard", true)
                .buildAndExpand(id).toUri();
        restTemplate.exchange(uri, HttpMethod.DELETE, null, Void.class);
    }
}

@Component
class Accounts {

    private final RestClient client = RestClient.builder()
            .uriBuilderFactory(new DefaultUriBuilderFactory("http://accounts:6060")).build();

    String account(long id) {
        return client.get().uri(builder -> builder.path("/accounts/{id}").queryParam("full", true).build(id))
                .retrieve().body(String.class);
    }
}

@Component
class Audit {

    private final WebClient client = WebClient.create();

    String events() throws URISyntaxException {
        return client.get().uri(new URI("http://audit:4040/events")).retrieve().bodyToMono(String.class).block();
    }
}

@RestController
class UrisController {

    private final Ledger ledger;
    private final Accounts accounts;
    private final Audit audit;
    private final TicketClient tickets;

    UrisController(Ledger ledger, Accounts accounts, Audit audit, TicketClient tickets) {
        this.ledger = ledger;
        this.accounts = accounts;
        this.audit = audit;
        this.tickets = tickets;
    }

    @GetMapping("/summary/{id}")
    String summary(@PathVariable long id) throws URISyntaxException {
        ledger.remove(id);
        return ledger.entry() + accounts.account(id) + audit.events() + tickets.ticket(id);
    }
}
