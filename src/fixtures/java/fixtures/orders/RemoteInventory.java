package fixtures.orders;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
class RemoteInventory {

    private final RestClient client = RestClient.create("http://inventory:8080");

    Integer stock(String sku) {
        return client.get().uri("/stock/{sku}", sku).retrieve().body(Integer.class);
    }

    void reserve(String sku) {
        client.post().uri("/reservations/{sku}", sku).retrieve().toBodilessEntity();
    }
}
