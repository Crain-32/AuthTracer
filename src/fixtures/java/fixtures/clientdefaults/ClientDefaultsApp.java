package fixtures.clientdefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Decision 0083 and OAUTH-05: client beans whose OAuth2 support picks the token without the request naming a
 * registration (the signed-in user's authorized client, a resolver of the application's, a default registration
 * from the environment), a bean named apart from its method, one a factory of the application's makes, and a client
 * given to a class whose field names none of the beans.
 */
@Configuration
class ClientDefaultsConfig {

    /**
     * The reference's servlet WebClient, which sends the signed-in user's authorized client by default.
     */
    @Bean
    WebClient profiles(WebClient.Builder builder, OAuth2AuthorizedClientManager manager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager);
        oauth2.setDefaultOAuth2AuthorizedClient(true);
        return builder.baseUrl("http://profiles:8080").apply(oauth2.oauth2Configuration()).build();
    }

    @Bean
    RestClient billing(RestClient.Builder builder, OAuth2AuthorizedClientManager manager) {
        OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(manager);
        interceptor.setClientRegistrationIdResolver(request -> "billing");
        return builder.baseUrl("http://billing:8080").requestInterceptor(interceptor).build();
    }

    @Bean
    WebClient tenants(WebClient.Builder builder, OAuth2AuthorizedClientManager manager, Environment environment) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager);
        oauth2.setDefaultClientRegistrationId(environment.getProperty("tenants.registration"));
        return builder.baseUrl("http://tenants:8080").filter(oauth2).build();
    }

    @Bean(name = "auditClient")
    RestClient audit(RestClient.Builder builder) {
        return builder.baseUrl("http://audit:8080")
                .requestInterceptor(new BasicAuthenticationInterceptor("audit", "secret")).build();
    }

    @Bean
    RestClient archive(ClientFactory factory) {
        return factory.create("http://archive:8080");
    }
}

@Component
class ClientFactory {

    RestClient create(String baseUrl) {
        return RestClient.create(baseUrl);
    }
}

@Component
class DefaultsCalls {

    private final WebClient profiles;
    private final RestClient billing;
    private final WebClient tenants;
    private final RestClient auditClient;
    private final RestClient archive;

    DefaultsCalls(WebClient profiles, RestClient billing, WebClient tenants, RestClient auditClient,
            RestClient archive) {
        this.profiles = profiles;
        this.billing = billing;
        this.tenants = tenants;
        this.auditClient = auditClient;
        this.archive = archive;
    }

    String all() {
        return profiles.get().uri("/profiles/me").retrieve().bodyToMono(String.class).block()
                + billing.get().uri("/invoices").retrieve().body(String.class)
                + tenants.get().uri("/tenants").retrieve().bodyToMono(String.class).block()
                + auditClient.get().uri("/audit").retrieve().body(String.class)
                + archive.get().uri("/archive").retrieve().body(String.class);
    }
}

/**
 * Its field names none of the RestClient beans, which send different credentials.
 */
@Component
class AmbiguousCalls {

    private final RestClient client;

    AmbiguousCalls(RestClient client) {
        this.client = client;
    }

    String any() {
        return client.get().uri("/any").retrieve().body(String.class);
    }
}

@RestController
class ClientDefaultsController {

    private final DefaultsCalls calls;
    private final AmbiguousCalls ambiguous;

    ClientDefaultsController(DefaultsCalls calls, AmbiguousCalls ambiguous) {
        this.calls = calls;
        this.ambiguous = ambiguous;
    }

    @GetMapping("/all")
    String all() {
        return calls.all() + ambiguous.any();
    }
}
