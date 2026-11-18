package fixtures.ownclients;

import java.io.IOException;

import org.springframework.boot.restclient.RestClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.web.client.support.OAuth2RestClientHttpServiceGroupConfigurer;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import org.springframework.web.service.registry.ImportHttpServices;

/**
 * Decision 0083: each call has the credentials of the client it is made on, where that client is built: clients a
 * class builds from a static factory or from Boot's builder, client beans, an HTTP service
 * group's client, a hand-wired HTTP interface, and OAuth2 interceptors that need the request to name a registration.
 */
@Configuration
@ImportHttpServices(group = "partner", types = PartnerApi.class)
class ClientBeans {

    @Bean
    RestClient relayed(RestClient.Builder builder) {
        return builder.baseUrl("http://relayed:8080").requestInterceptor(new BearerRelay()).build();
    }

    @Bean
    RestClient partners(RestClient.Builder builder, OAuth2AuthorizedClientManager manager) {
        return builder.baseUrl("http://partners:8080").requestInterceptor(new OAuth2ClientHttpRequestInterceptor(manager))
                .build();
    }

    @Bean
    WebClient reports(WebClient.Builder builder, OAuth2AuthorizedClientManager manager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager);
        oauth2.setDefaultClientRegistrationId("backend");
        return builder.baseUrl("http://reports:8080").filter(oauth2).build();
    }

    @Bean
    WebClient ledgers(WebClient.Builder builder, OAuth2AuthorizedClientManager manager) {
        return builder.baseUrl("http://ledgers:8080").filter(new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager))
                .build();
    }

    @Bean
    RestTemplate template() {
        RestTemplate template = new RestTemplate();
        template.getInterceptors().add(new BearerRelay());
        return template;
    }

    @Bean
    OAuth2RestClientHttpServiceGroupConfigurer groups(OAuth2AuthorizedClientManager manager) {
        return OAuth2RestClientHttpServiceGroupConfigurer.from(manager);
    }

    @Bean
    RestClientCustomizer apiKey() {
        return builder -> builder.defaultHeader("Authorization", "ApiKey 7f3a");
    }

    @Bean
    LedgerApi ledger(OAuth2AuthorizedClientManager manager) {
        RestClient client = RestClient.builder().baseUrl("http://ledger:8080")
                .requestInterceptor(new OAuth2ClientHttpRequestInterceptor(manager)).build();
        return HttpServiceProxyFactory.builderFor(RestClientAdapter.create(client))
                .httpRequestValuesProcessor(ClientRegistrationIdProcessor.DEFAULT_INSTANCE).build()
                .createClient(LedgerApi.class);
    }
}

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
 * Its own client, from a static factory: none of the client beans', and no customizer's.
 */
@Component
class OwnCalls {

    private final RestClient client = RestClient.create("http://own:8080");

    private final WebClient web = WebClient.create("http://own:8080");

    private final RestTemplate rest = new RestTemplate();

    String own() {
        return client.get().uri("/own").retrieve().body(String.class)
                + web.get().uri("/own/web").retrieve().bodyToMono(String.class).block()
                + rest.getForObject("http://own:8080/own/template", String.class);
    }
}

/**
 * Its own client, from Boot's builder: the customizers', not the client beans'.
 */
@Component
class BuilderCalls {

    private final RestClient client;

    BuilderCalls(RestClient.Builder builder) {
        this.client = builder.baseUrl("http://built:8080").build();
    }

    String built() {
        return client.get().uri("/built").retrieve().body(String.class);
    }
}

/**
 * Given client beans: by name, a token for the registration the request names (none: the customizer's key), a
 * default registration, an authorized client the request carries (none, nothing sent), the template bean's
 * interceptor.
 */
@Component
class InjectedCalls {

    private final RestClient relayed;
    private final RestClient partners;
    private final WebClient reports;
    private final WebClient ledgers;
    private final RestTemplate template;

    InjectedCalls(RestClient relayed, RestClient partners, WebClient reports, WebClient ledgers, RestTemplate template) {
        this.relayed = relayed;
        this.partners = partners;
        this.reports = reports;
        this.ledgers = ledgers;
        this.template = template;
    }

    String authorized(OAuth2AuthorizedClient client) {
        return ledgers.get().uri("/ledgers/authorized")
                .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(client))
                .retrieve().bodyToMono(String.class).block();
    }

    String unauthorized() {
        return ledgers.get().uri("/ledgers/plain").retrieve().bodyToMono(String.class).block();
    }

    String injected() {
        return relayed.get().uri("/injected").retrieve().body(String.class)
                + partners.get().uri("/partners/named").attributes(
                        org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver
                                .clientRegistrationId("backend")).retrieve().body(String.class)
                + template.getForObject("http://templated:8080/templated", String.class);
    }

    String unnamed() {
        return partners.get().uri("/partners/unnamed").retrieve().body(String.class)
                + reports.get().uri("/reports").retrieve().bodyToMono(String.class).block();
    }
}

interface PartnerApi {

    @GetExchange("/partner/orders")
    @ClientRegistrationId("backend")
    String orders();

    @GetExchange("/partner/catalog")
    String catalog();
}

interface LedgerApi {

    @GetExchange("/ledger")
    @ClientRegistrationId(registrationId = "user-login")
    String ledger();
}

@RestController
class OwnClientsController {

    private final OwnCalls own;
    private final BuilderCalls built;
    private final InjectedCalls injected;
    private final PartnerApi partner;
    private final LedgerApi ledger;

    OwnClientsController(OwnCalls own, BuilderCalls built, InjectedCalls injected, PartnerApi partner,
            LedgerApi ledger) {
        this.own = own;
        this.built = built;
        this.injected = injected;
        this.partner = partner;
        this.ledger = ledger;
    }

    @GetMapping("/all")
    String all(OAuth2AuthorizedClient client) {
        return own.own() + built.built() + injected.injected() + injected.unnamed() + injected.authorized(client)
                + injected.unauthorized() + partner.orders() + partner.catalog() + ledger.ledger();
    }
}
