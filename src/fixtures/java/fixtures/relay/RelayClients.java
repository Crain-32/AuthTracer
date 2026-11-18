package fixtures.relay;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

import java.io.IOException;

import fixtures.relaylib.VendorInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.annotation.GetExchange;

@Component
class WebClientRelay {

    private final WebClient client = WebClient.builder().baseUrl("http://down:9001")
            .filter(new ServletBearerExchangeFilterFunction()).build();

    String call() {
        return client.get().uri("/relay/webclient").retrieve().bodyToMono(String.class).block();
    }
}

@Component
class OAuth2Calls {

    private final RestClient client;

    OAuth2Calls(OAuth2AuthorizedClientManager manager) {
        this.client = RestClient.builder().baseUrl("http://down:9001")
                .requestInterceptor(new OAuth2ClientHttpRequestInterceptor(manager)).build();
    }

    String call() {
        return client.get().uri("/relay/oauth2").retrieve().body(String.class);
    }
}

@Component
class RegistrationCalls {

    private final RestClient client;

    RegistrationCalls(OAuth2AuthorizedClientManager manager) {
        this.client = RestClient.builder().baseUrl("http://down:9001")
                .requestInterceptor(new OAuth2ClientHttpRequestInterceptor(manager)).build();
    }

    String asUser() {
        return client.get().uri("/relay/user").attributes(clientRegistrationId("user-login")).retrieve()
                .body(String.class);
    }

    String asService() {
        return client.get().uri("/relay/service").attributes(clientRegistrationId("backend")).retrieve()
                .body(String.class);
    }
}

@Component
class StaticCalls {

    private final RestClient client = RestClient.builder().baseUrl("http://down:9001")
            .defaultHeaders(headers -> headers.setBasicAuth("svc", "secret")).build();

    String call() {
        return client.get().uri("/relay/static").retrieve().body(String.class);
    }
}

@Component
class PlainCalls {

    private final RestClient client = RestClient.create("http://down:9001");

    String call() {
        return client.get().uri("/relay/plain").retrieve().body(String.class);
    }
}

/**
 * Copies the incoming request's Authorization header onto the outgoing call.
 */
class CopyAuthorizationInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        HttpServletRequest incoming = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                .getRequest();
        request.getHeaders().set("Authorization", incoming.getHeader("Authorization"));
        return execution.execute(request, body);
    }
}

@Component
class CustomRelay {

    private final RestTemplate restTemplate = new RestTemplate();

    CustomRelay() {
        restTemplate.getInterceptors().add(new CopyAuthorizationInterceptor());
    }

    String call() {
        return restTemplate.getForObject("http://down:9001/relay/custom", String.class);
    }
}

@Component
class LambdaRelay {

    private final RestClient client = RestClient.builder().baseUrl("http://down:9001")
            .requestInterceptor((request, body, execution) -> {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> token) {
                    request.getHeaders().setBearerAuth(token.getToken().getTokenValue());
                }
                return execution.execute(request, body);
            }).build();

    String call() {
        return client.get().uri("/relay/lambda").retrieve().body(String.class);
    }
}

@Component
class LibraryCalls {

    private final RestClient client = RestClient.builder().baseUrl("http://down:9001")
            .requestInterceptor(new VendorInterceptor()).build();

    String call() {
        return client.get().uri("/relay/library").retrieve().body(String.class);
    }
}

interface PartnerApi {

    @GetExchange("http://partner:9002/partner/data")
    @ClientRegistrationId("partner")
    String data();
}
