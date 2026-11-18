package fixtures.relaybeans;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Client beans with different credentials: each call has its own client's, not the strongest of them all.
 */
@Configuration
class ClientBeans {

    @Bean
    RestClient orders(RestClient.Builder builder, OAuth2AuthorizedClientManager manager) {
        return builder.baseUrl("http://orders:9001").requestInterceptor(new OAuth2ClientHttpRequestInterceptor(manager))
                .build();
    }

    @Bean
    RestClient audit(RestClient.Builder builder) {
        return builder.baseUrl("http://audit:9003").build();
    }

    @Bean
    WebClient profile(WebClient.Builder builder) {
        return builder.baseUrl("http://profiles:9002").filter(new ServletBearerExchangeFilterFunction()).build();
    }
}

/**
 * Given the orders client: its field is named after the bean.
 */
@Component
class OrderCalls {

    private final RestClient orders;

    OrderCalls(RestClient orders) {
        this.orders = orders;
    }

    String order() {
        return orders.get().uri("/orders").retrieve().body(String.class);
    }
}

/**
 * The only WebClient bean.
 */
@Component
class ProfileCalls {

    private final WebClient client;

    ProfileCalls(WebClient client) {
        this.client = client;
    }

    String profile() {
        return client.get().uri("/profiles").retrieve().bodyToMono(String.class).block();
    }
}

/**
 * One of the two RestClient beans, which one AuthTracer can't tell.
 */
@Component
class SomeCalls {

    private final RestClient client;

    SomeCalls(RestClient client) {
        this.client = client;
    }

    String some() {
        return client.get().uri("/some").retrieve().body(String.class);
    }
}

@RestController
class RelayBeansController {

    private final OrderCalls orders;
    private final ProfileCalls profiles;
    private final SomeCalls some;

    RelayBeansController(OrderCalls orders, ProfileCalls profiles, SomeCalls some) {
        this.orders = orders;
        this.profiles = profiles;
        this.some = some;
    }

    @GetMapping("/all")
    String all() {
        return orders.order() + profiles.profile() + some.some();
    }
}
