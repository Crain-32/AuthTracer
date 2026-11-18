package fixtures.relaycustomizer;

import java.io.IOException;

import org.springframework.boot.restclient.RestClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * The relay is added to every client built from Boot's RestClient.Builder, not where the client is built.
 */
@Configuration
class CustomizerApp {

    @Bean
    RestClientCustomizer relayToken() {
        return builder -> builder.requestInterceptor(new RelayInterceptor());
    }
}

class RelayInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        request.getHeaders().setBearerAuth(token());
        return execution.execute(request, body);
    }

    private static String token() {
        return String.valueOf(SecurityContextHolder.getContext().getAuthentication().getCredentials());
    }
}

@Component
class Downstream {

    private final RestClient client;

    Downstream(RestClient.Builder builder) {
        this.client = builder.baseUrl("http://down:9001").build();
    }

    String call() {
        return client.get().uri("/customized").retrieve().body(String.class);
    }
}

@RestController
class CustomizedController {

    private final Downstream downstream;

    CustomizedController(Downstream downstream) {
        this.downstream = downstream;
    }

    @GetMapping("/customized")
    String customized() {
        return downstream.call();
    }
}
