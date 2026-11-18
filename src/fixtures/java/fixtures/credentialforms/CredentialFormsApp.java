package fixtures.credentialforms;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

/**
 * Credentials set in the other ways: a class's own interceptor on whichever of several client beans it is given,
 * an interceptor lambda that asks an application interface for the token, and an HTTP interface whose every
 * method uses one OAuth2 registration.
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
}

class ApiKeyInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        request.getHeaders().set("Authorization", "ApiKey 3c1d7e");
        return execution.execute(request, body);
    }
}

/**
 * Its own API key, whichever RestClient bean it is given.
 */
@Component
class KeyedCalls {

    private final RestClient client;

    KeyedCalls(RestClient client) {
        this.client = client.mutate().requestInterceptor(new ApiKeyInterceptor()).build();
    }

    String keyed() {
        return client.get().uri("/keyed").retrieve().body(String.class);
    }
}

interface TokenSource {

    String token();
}

/**
 * A token from the application's TokenSource, which nothing in the application implements.
 */
@Component
class TokenCalls {

    private final RestClient client;

    TokenCalls(RestClient client, TokenSource tokens) {
        this.client = client.mutate().requestInterceptor((request, body, execution) -> {
            request.getHeaders().setBearerAuth(tokens.token());
            return execution.execute(request, body);
        }).build();
    }

    String tokened() {
        return client.get().uri("/tokened").retrieve().body(String.class);
    }
}

@ClientRegistrationId("partner")
@HttpExchange("http://partner:8080")
interface PartnerApi {

    @GetExchange("/partner/orders")
    String orders();
}

@RestController
class CredentialController {

    private final KeyedCalls keyed;
    private final TokenCalls tokened;
    private final PartnerApi partner;

    CredentialController(KeyedCalls keyed, TokenCalls tokened, PartnerApi partner) {
        this.keyed = keyed;
        this.tokened = tokened;
        this.partner = partner;
    }

    @GetMapping("/all")
    String all() {
        return keyed.keyed() + tokened.tokened() + partner.orders();
    }
}
