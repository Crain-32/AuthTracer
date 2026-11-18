package fixtures.tokentrace;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Decision 0083 amended: the Authorization value an interceptor sets, followed back through fields, parameters and
 * other classes to where it comes from.
 */
@Component
class TokenHolder {

    private String token;

    void set(String token) {
        this.token = token;
    }

    String get() {
        return token;
    }
}

/**
 * Keeps the incoming request's Authorization header for the calls the request makes.
 */
@Component
class CaptureFilter extends OncePerRequestFilter {

    private final TokenHolder holder;

    CaptureFilter(TokenHolder holder) {
        this.holder = holder;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        holder.set(request.getHeader("Authorization"));
        chain.doFilter(request, response);
    }
}

class HolderInterceptor implements ClientHttpRequestInterceptor {

    private final TokenHolder holder;

    HolderInterceptor(TokenHolder holder) {
        this.holder = holder;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        request.getHeaders().set("Authorization", holder.get());
        return execution.execute(request, body);
    }
}

/**
 * The header the holder kept: the caller's.
 */
@Component
class HolderCalls {

    private final RestClient client;

    HolderCalls(TokenHolder holder) {
        this.client = RestClient.builder().baseUrl("http://held:8080").requestInterceptor(new HolderInterceptor(holder))
                .build();
    }

    String held() {
        return client.get().uri("/held").retrieve().body(String.class);
    }
}

interface TokenProvider {

    String token();
}

@Component
class ContextTokens implements TokenProvider {

    @Override
    public String token() {
        return ((JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getToken()
                .getTokenValue();
    }
}

/**
 * A token from an interface whose implementation reads the security context: the caller's.
 */
@Component
class ProviderCalls {

    private final RestClient client;

    ProviderCalls(TokenProvider provider) {
        this.client = RestClient.builder().baseUrl("http://provided:8080").requestInterceptor((request, body, execution) -> {
            request.getHeaders().setBearerAuth(provider.token());
            return execution.execute(request, body);
        }).build();
    }

    String provided() {
        return client.get().uri("/provided").retrieve().body(String.class);
    }
}

class KeyInterceptor implements ClientHttpRequestInterceptor {

    private final String key;

    KeyInterceptor(String key) {
        this.key = key;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        request.getHeaders().set("Authorization", "ApiKey " + key);
        return execution.execute(request, body);
    }
}

/**
 * A key from the configuration, through the interceptor's constructor: fixed.
 */
@Component
class KeyCalls {

    private final RestClient client;

    KeyCalls(@Value("${partner.key}") String key) {
        this.client = RestClient.builder().baseUrl("http://configured:8080").requestInterceptor(new KeyInterceptor(key))
                .build();
    }

    String configured() {
        return client.get().uri("/configured").retrieve().body(String.class);
    }
}

@Component
class ClientTokens {

    private final OAuth2AuthorizedClientManager manager;

    ClientTokens(OAuth2AuthorizedClientManager manager) {
        this.manager = manager;
    }

    String bearer() {
        return "Bearer " + fetch();
    }

    private String fetch() {
        return manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("partner").principal("service")
                .build()).getAccessToken().getTokenValue();
    }
}

/**
 * A token an authorized-client manager gives, two classes away: the service's own.
 */
@Component
class FetchCalls {

    private final RestClient client;

    FetchCalls(ClientTokens tokens) {
        this.client = RestClient.builder().baseUrl("http://fetched:8080").requestInterceptor((request, body, execution) -> {
            request.getHeaders().set("Authorization", tokens.bearer());
            return execution.execute(request, body);
        }).build();
    }

    String fetched() {
        return client.get().uri("/fetched").retrieve().body(String.class);
    }
}

@Component
class LateTokens {

    private String token;

    String get() {
        return token;
    }
}

/**
 * A field nothing in the application sets: AuthTracer can't tell what is sent.
 */
@Component
class LateCalls {

    private final RestClient client;

    LateCalls(LateTokens tokens) {
        this.client = RestClient.builder().baseUrl("http://late:8080").requestInterceptor((request, body, execution) -> {
            request.getHeaders().setBearerAuth(tokens.get());
            return execution.execute(request, body);
        }).build();
    }

    String late() {
        return client.get().uri("/late").retrieve().body(String.class);
    }
}

@RestController
class TokenTraceController {

    private final HolderCalls held;
    private final ProviderCalls provided;
    private final KeyCalls configured;
    private final FetchCalls fetched;
    private final LateCalls late;

    TokenTraceController(HolderCalls held, ProviderCalls provided, KeyCalls configured, FetchCalls fetched,
            LateCalls late) {
        this.held = held;
        this.provided = provided;
        this.configured = configured;
        this.fetched = fetched;
        this.late = late;
    }

    @GetMapping("/all")
    String all() {
        return held.held() + provided.provided() + configured.configured() + fetched.fetched() + late.late();
    }
}
