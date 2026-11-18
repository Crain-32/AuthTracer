package fixtures.clients;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Two clients built from one builder, each with its own base URL.
 */
@Component
class TwoServices {

    private final RestClient users;
    private final RestClient purchases;

    TwoServices(RestClient.Builder builder) {
        this.users = builder.clone().baseUrl("http://users:8081").build();
        this.purchases = builder.clone().baseUrl("http://purchases:8082").build();
    }

    String user(String id) {
        return users.get().uri("/users/{id}", id).retrieve().body(String.class);
    }

    String purchase(String id) {
        return purchases.get().uri("/purchases/{id}", id).retrieve().body(String.class);
    }
}
