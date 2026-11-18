package fixtures.clients;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
class ReactivePricing {

    private final WebClient client = WebClient.builder().baseUrl("http://pricing:8081").build();

    Price price(String id) {
        return client.get().uri("/prices/{id}", id).retrieve().bodyToMono(Price.class).block();
    }

    void history(String id) {
        client.get().uri("/prices/{id}/history", id).retrieve().bodyToFlux(Price.class).collectList().block();
    }

    /**
     * No uri(..): the request goes to the base URL.
     */
    Price current() {
        return client.get().header("X-Region", "eu").retrieve().bodyToMono(Price.class).block();
    }
}
