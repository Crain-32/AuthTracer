package fixtures.clients;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * A client built in a @Bean method and injected where it's used.
 */
@Configuration
class PartnerClientConfig {

    @Bean
    RestClient partnerClient() {
        return RestClient.builder().baseUrl("http://partner:7070").build();
    }
}

@Component
class PartnerCalls {

    private final RestClient client;

    PartnerCalls(RestClient client) {
        this.client = client;
    }

    String partner(String id) {
        return client.get().uri("/partners/{id}", id).retrieve().body(String.class);
    }
}
