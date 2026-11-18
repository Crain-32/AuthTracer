package fixtures.registrationgrants;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Client registrations whose grant type Boot defaults: github is one of Spring Security's common providers and
 * corporate's provider has an issuer, so both are authorization code, a signed-in user's token. The legacy one asks
 * for the password grant, which Spring Security 7.1.1 no longer has.
 */
@SpringBootApplication
class RegistrationGrantsApp {
}

@RestController
class GrantsController {

    private final GrantCalls calls;

    GrantsController(GrantCalls calls) {
        this.calls = calls;
    }

    @GetMapping("/sync")
    String sync() {
        return calls.github() + calls.corporate() + calls.legacy();
    }
}

@Component
class GrantCalls {

    private final RestClient client;

    GrantCalls(OAuth2AuthorizedClientManager manager) {
        this.client = RestClient.builder().baseUrl("http://down:9001")
                .requestInterceptor(new OAuth2ClientHttpRequestInterceptor(manager)).build();
    }

    String github() {
        return client.get().uri("/repos").attributes(clientRegistrationId("github")).retrieve().body(String.class);
    }

    String corporate() {
        return client.get().uri("/directory").attributes(clientRegistrationId("corporate")).retrieve()
                .body(String.class);
    }

    String legacy() {
        return client.get().uri("/ledger").attributes(clientRegistrationId("legacy")).retrieve().body(String.class);
    }
}
