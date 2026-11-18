package fixtures.clientbuilds;

import java.io.IOException;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Decision 0083 amended: a method that builds several clients gives each what is set on it, not the strongest of the
 * method.
 */
class BearerRelay implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken jwt) {
            request.getHeaders().setBearerAuth(jwt.getToken().getTokenValue());
        }
        return execution.execute(request, body);
    }
}

/**
 * Two clients built in one constructor: only one relays.
 */
@Component
class TwoClients {

    private final RestClient relayed;
    private final RestClient plain;

    TwoClients() {
        this.relayed = RestClient.builder().baseUrl("http://relayed:8080").requestInterceptor(new BearerRelay()).build();
        this.plain = RestClient.create("http://plain:8080");
    }

    String calls() {
        return relayed.get().uri("/two/relayed").retrieve().body(String.class)
                + plain.get().uri("/two/plain").retrieve().body(String.class);
    }
}

/**
 * Field initializers, which the constructor runs: a fixed key on one client, nothing on the other.
 */
@Component
class FieldClients {

    private final RestClient keyed = RestClient.builder().baseUrl("http://keyed:8080")
            .defaultHeader("Authorization", "ApiKey 7f3a").build();

    private final RestClient open = RestClient.builder().baseUrl("http://open:8080").build();

    String calls() {
        return keyed.get().uri("/fields/keyed").retrieve().body(String.class)
                + open.get().uri("/fields/open").retrieve().body(String.class);
    }
}

/**
 * One builder for two clients: what is set on it is on both, as Spring's builders are mutable.
 */
@Component
class SharedBuilder {

    private final RestClient first;
    private final RestClient second;

    SharedBuilder(RestClient.Builder builder) {
        builder.requestInterceptor(new BearerRelay());
        this.first = builder.baseUrl("http://first:8080").build();
        this.second = builder.baseUrl("http://second:8080").build();
    }

    String calls() {
        return first.get().uri("/shared/first").retrieve().body(String.class)
                + second.get().uri("/shared/second").retrieve().body(String.class);
    }
}

/**
 * Two templates: the interceptor goes on one, through its interceptor list.
 */
@Component
class Templates {

    private final RestTemplate relayed = new RestTemplate();
    private final RestTemplate plain = new RestTemplate();

    Templates() {
        relayed.getInterceptors().add(new BearerRelay());
    }

    String calls() {
        return relayed.getForObject("http://relayed:8080/templates/relayed", String.class)
                + plain.getForObject("http://plain:8080/templates/plain", String.class);
    }
}

/**
 * A filter function with a default registration on one WebClient, configured before both are built.
 */
@Component
class WebClients {

    private final WebClient reports;
    private final WebClient open;

    WebClients(OAuth2AuthorizedClientManager manager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager);
        oauth2.setDefaultClientRegistrationId("reports");
        this.open = WebClient.create("http://open:8080");
        this.reports = WebClient.builder().baseUrl("http://reports:8080").filter(oauth2).build();
    }

    String calls() {
        return reports.get().uri("/web/reports").retrieve().bodyToMono(String.class).block()
                + open.get().uri("/web/open").retrieve().bodyToMono(String.class).block();
    }
}

@RestController
class ClientBuildsController {

    private final TwoClients two;
    private final FieldClients fields;
    private final SharedBuilder shared;
    private final Templates templates;
    private final WebClients web;

    ClientBuildsController(TwoClients two, FieldClients fields, SharedBuilder shared, Templates templates,
            WebClients web) {
        this.two = two;
        this.fields = fields;
        this.shared = shared;
        this.templates = templates;
        this.web = web;
    }

    @GetMapping("/all")
    String all() {
        return two.calls() + fields.calls() + shared.calls() + templates.calls() + web.calls();
    }
}
