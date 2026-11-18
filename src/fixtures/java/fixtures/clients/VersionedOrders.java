package fixtures.clients;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * A base URL with a path: the request's path goes under it.
 */
@Component
class VersionedOrders {

    private final RestClient client = RestClient.builder().baseUrl("http://orders:8080/api/v1").build();

    String order(String id) {
        return client.get().uri("/orders/{id}", id).retrieve().body(String.class);
    }
}
