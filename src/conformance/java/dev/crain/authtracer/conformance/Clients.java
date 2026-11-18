package dev.crain.authtracer.conformance;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpSession;

import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

/**
 * Sends a probe's caller to an endpoint of a booted fixture and says what Spring did: denied it (401, 403, a redirect
 * to sign in, or an access-denied or authentication exception), let it through (any other answer from the handler,
 * or a filter's redirect that isn't to sign in), or neither for sure. An endpoint a caller can reach more than one way
 * is sent each way ({@link #ways}).
 */
final class Clients {

    enum Outcome {
        DENIED, ALLOWED,
        /**
         * A 4xx other than 401/403/404/405: the request failed before the handler ran, so checks it makes weren't
         * reached. Also an endpoint this environment doesn't serve (Actuator on a port of its own).
         */
        UNREACHED,
        NOT_FOUND, ERROR
    }

    /**
     * @param body what the response carried, when the handler answered; {@code null} otherwise
     * @param contentType the response's media type, {@code null} when it has none
     */
    record Result(Outcome outcome, String detail, String body, String contentType) {

        Result(Outcome outcome, String detail) {
            this(outcome, detail, null, null);
        }
    }

    interface Client {
        Result send(Expectation endpoint, Callers.Probe probe);
    }

    private static final Set<String> SAFE = Set.of("GET", "HEAD", "OPTIONS");
    /**
     * The methods a mapping for any method ({@code *}) is sent with.
     */
    private static final List<String> ANY_METHOD = List.of("GET", "POST", "PUT", "DELETE", "PATCH");
    /**
     * Where Spring Security's ExceptionTranslationFilter keeps a request it sends to sign in
     * (HttpSessionRequestCache), to come back to it.
     */
    private static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
    private static final Pattern SIGN_IN = Pattern.compile("(?i)log-?in|sign-?in|log-?on|/oauth2/authorization/");
    private static final Pattern SIGN_OUT = Pattern.compile("(?i)log-?out|sign-?out");
    private static final String SPRING_SECURITY_FILTER = "springSecurityFilterChain";
    private static final String WEB_FILTER_CHAIN = "org.springframework.security.web.server.WebFilterChainProxy";

    private Clients() {
    }

    static Client servlet(WebApplicationContext context) {
        DefaultMockMvcBuilder builder = MockMvcBuilders.webAppContextSetup(context);
        if (context.containsBean(SPRING_SECURITY_FILTER)) {
            builder.apply(org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
                    .springSecurity());
        }
        return ways(new Servlet(builder.build(), context.getEnvironment()), context.getEnvironment());
    }

    static Client reactive(ApplicationContext context) {
        WebTestClient.MockServerSpec<?> spec = WebTestClient.bindToApplicationContext(context);
        boolean secured;
        try {
            secured = context.getBeanNamesForType(Class.forName(WEB_FILTER_CHAIN)).length > 0;
        } catch (ClassNotFoundException e) {
            secured = false;
        }
        if (secured) {
            spec.apply(springSecurity());
        }
        return ways(new Reactive(spec.configureClient().responseTimeout(Duration.ofSeconds(10)).build()),
                context.getEnvironment());
    }

    /**
     * Sends an endpoint each way a caller can reach it, as the graph reads it: its requirement is the weakest way's.
     * A mapping for any method ({@code *}) takes each method, and the error page ({@code server.error.path}) also
     * answers, on the Servlet stack, the error dispatch of any request that failed. A caller is let in when one way
     * lets it in, denied when none does and one denies it.
     */
    static Client ways(Client client, Environment environment) {
        String errorPath = environment.getProperty("server.error.path", "/error");
        return (endpoint, probe) -> {
            String management = managementServer(environment, endpoint);
            if (management != null) {
                return new Result(Outcome.UNREACHED, endpoint.endpoint() + " -> " + management);
            }
            List<Result> results = new ArrayList<>();
            for (String method : endpoint.method().equals("*") ? ANY_METHOD : List.of(endpoint.method())) {
                Expectation way = new Expectation(endpoint.fixture(), method, endpoint.route(), endpoint.params(),
                        endpoint.clauses(), endpoint.requirement());
                results.add(client.send(way, probe));
                if (endpoint.route().equals(errorPath) && client instanceof Servlet servlet) {
                    results.add(servlet.send(way, probe, DispatcherType.ERROR));
                }
            }
            if (results.size() == 1) {
                return results.getFirst();
            }
            Result chosen = results.stream().filter(result -> result.outcome() == Outcome.ALLOWED).findFirst()
                    .or(() -> results.stream().filter(result -> result.outcome() == Outcome.DENIED).findFirst())
                    .orElse(results.getFirst());
            return new Result(chosen.outcome(), String.join("; ", results.stream().map(Result::detail).toList()),
                    chosen.body(), chosen.contentType());
        };
    }

    /**
     * Why the endpoint isn't served here, or {@code null}: Actuator on a port of its own
     * ({@code management.server.port}) runs in a server of its own, which a mock environment doesn't start, and Boot's
     * management request matchers tell its requests apart from the application's.
     */
    private static String managementServer(Environment environment, Expectation endpoint) {
        String port = environment.getProperty("management.server.port");
        if (port == null || port.equals("-1") || port.equals(environment.getProperty("server.port", "8080"))) {
            return null;
        }
        String base = (environment.getProperty("management.server.base-path", "")
                + environment.getProperty("management.endpoints.web.base-path", "/actuator")).replaceAll("/+", "/");
        base = base.length() > 1 && base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        boolean actuator = base.equals("/") || endpoint.route().equals(base) || endpoint.route().startsWith(base + "/");
        return actuator ? "served by the management server on port " + port + ", which a mock environment doesn't start"
                : null;
    }

    /**
     * The path a route is requested at: variables filled with {@code 1}, a captured rest with {@code a/b}, wildcards
     * with {@code x}.
     */
    static String fill(String route) {
        return route.replaceAll("\\{\\*[^}]*}", "a/b").replaceAll("\\{[^}]*}", "1").replace("**", "x")
                .replace("*", "x");
    }

    private static String method(Expectation endpoint) {
        return endpoint.method().equals("*") ? "GET" : endpoint.method();
    }

    private static boolean security(Throwable thrown) {
        for (Throwable cause = thrown; cause != null; cause = cause.getCause()) {
            if (cause instanceof AccessDeniedException || cause instanceof AuthenticationException) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param filterAnswered a filter answered, not a handler
     * @param startsAuthentication Spring Security kept the request, to come back to it after signing in
     */
    private static Outcome status(int status, boolean filterAnswered, boolean startsAuthentication, String location) {
        if (status == 401 || status == 403) {
            return Outcome.DENIED;
        }
        // A page named for signing in: WebFlux's request cache keeps only requests that ask for HTML, so a redirect
        // there doesn't always keep the request.
        boolean toSignIn = location != null && SIGN_IN.matcher(location).find() && !SIGN_OUT.matcher(location).find();
        if (status >= 300 && status < 400 && (startsAuthentication || toSignIn)) {
            return Outcome.DENIED;
        }
        if (status >= 300 && status < 400 && filterAnswered) {
            // What the filter is for (a logout, an OAuth2 authorization request), which no rule denied.
            return Outcome.ALLOWED;
        }
        if (status == 404 || status == 405) {
            return Outcome.NOT_FOUND;
        }
        if (status >= 500) {
            return Outcome.ERROR;
        }
        return status >= 400 ? Outcome.UNREACHED : Outcome.ALLOWED;
    }

    static String root(Throwable thrown) {
        Throwable cause = thrown;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        String message = String.valueOf(cause.getMessage()).replaceAll("[\t\n\r]", " ");
        return cause.getClass().getSimpleName() + ": "
                + (message.length() > 240 ? message.substring(0, 240) + "..." : message);
    }

    /**
     * What a request carries besides its route's own parameters, filled in as Spring asks for it: a required
     * parameter or header it says is missing gets {@code 1}, a body it can't read {@code {}}, then {@code []}.
     */
    private record Filled(Map<String, String> params, Map<String, String> headers, String body) {

        static final Filled NONE = new Filled(Map.of(), Map.of(), null);
        static final int ROUNDS = 6;

        /**
         * What the request lacked, from the exception that answered it 400; {@code null} when it was something else.
         */
        Filled with(Exception lacked) {
            if (lacked instanceof MissingServletRequestParameterException parameter
                    && !params.containsKey(parameter.getParameterName())) {
                Map<String, String> more = new LinkedHashMap<>(params);
                more.put(parameter.getParameterName(), "1");
                return new Filled(more, headers, body);
            }
            if (lacked instanceof MissingRequestHeaderException header && !headers.containsKey(header.getHeaderName())) {
                Map<String, String> more = new LinkedHashMap<>(headers);
                more.put(header.getHeaderName(), "1");
                return new Filled(params, more, body);
            }
            if (lacked instanceof HttpMessageNotReadableException) {
                return body == null ? new Filled(params, headers, "{}")
                        : body.equals("{}") ? new Filled(params, headers, "[]") : null;
            }
            return null;
        }

        String describe() {
            List<String> parts = new ArrayList<>();
            params.keySet().forEach(name -> parts.add(name + "=1"));
            headers.keySet().forEach(name -> parts.add(name + ": 1"));
            if (body != null) {
                parts.add("body " + body);
            }
            return parts.isEmpty() ? "" : " (with " + String.join(", ", parts) + ")";
        }
    }

    /**
     * MockMvc with Spring Security's filters. The DispatcherServlet is mapped to {@code /} unless
     * {@code spring.mvc.servlet.path} says otherwise, so the servlet path is the whole path, as in a container.
     */
    private record Servlet(MockMvc mvc, Environment environment) implements Client {

        @Override
        public Result send(Expectation endpoint, Callers.Probe probe) {
            return send(endpoint, probe, DispatcherType.REQUEST);
        }

        /**
         * @param dispatch {@code ERROR} for the dispatch a container makes to the error page when a request fails
         */
        Result send(Expectation endpoint, Callers.Probe probe, DispatcherType dispatch) {
            Filled filled = Filled.NONE;
            Result result = null;
            for (int round = 0; round < Filled.ROUNDS && filled != null; round++) {
                Sent sent = send(endpoint, probe, dispatch, filled);
                result = sent.result();
                // A request Spring refused for what it lacked (400) never reached the handler's checks.
                filled = sent.status() == 400 && sent.lacked() != null ? filled.with(sent.lacked()) : null;
            }
            return result;
        }

        private record Sent(Result result, int status, Exception lacked) {

            Sent(Result result) {
                this(result, 0, null);
            }
        }

        private Sent send(Expectation endpoint, Callers.Probe probe, DispatcherType dispatch, Filled filled) {
            String method = method(endpoint);
            String contextPath = environment.getProperty("server.servlet.context-path", "");
            String servletPath = environment.getProperty("spring.mvc.servlet.path", "");
            servletPath = servletPath.equals("/") ? "" : servletPath;
            // Routes leave out the context and servlet paths.
            String route = fill(endpoint.route());
            String prefix = contextPath + servletPath;
            String path = !prefix.isEmpty() && route.startsWith(prefix + "/") ? route : prefix + route;
            MockHttpServletRequestBuilder request = MockMvcRequestBuilders.request(HttpMethod.valueOf(method), path);
            if (!contextPath.isEmpty()) {
                request.contextPath(contextPath);
            }
            String afterContext = path.substring(contextPath.length());
            String servlet = servletPath.isEmpty() ? afterContext : servletPath;
            // MockMvc refuses a servlet path that ends with '/': the path info is that '/'.
            request.servletPath(servlet.endsWith("/") ? servlet.substring(0, servlet.length() - 1) : servlet);
            params(endpoint, request);
            filled.params().forEach(request::param);
            filled.headers().forEach(request::header);
            if (filled.body() != null) {
                request.contentType(MediaType.APPLICATION_JSON).content(filled.body());
            }
            if (!SAFE.contains(method)) {
                request.with(csrf());
            }
            if (dispatch == DispatcherType.ERROR) {
                request.with(error -> {
                    error.setDispatcherType(DispatcherType.ERROR);
                    error.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, 500);
                    error.setAttribute(RequestDispatcher.ERROR_REQUEST_URI, contextPath + "/failed");
                    return error;
                });
            }
            if (probe.caller() != null) {
                request.with(authentication(probe.caller()));
                // An application without Spring Security's filters still runs its method checks on this thread.
                TestSecurityContextHolder.setAuthentication(probe.caller());
            }
            String sent = method + " " + path + filled.describe()
                    + (dispatch == DispatcherType.ERROR ? " (error dispatch)" : "");
            try {
                MvcResult result = mvc.perform(request).andReturn();
                if (result.getRequest().isAsyncStarted()) {
                    try {
                        result.getAsyncResult(10_000);
                    } catch (RuntimeException e) {
                        if (security(e)) {
                            return new Sent(new Result(Outcome.DENIED, sent + " -> async " + root(e)));
                        }
                    }
                    result = mvc.perform(MockMvcRequestBuilders.asyncDispatch(result)).andReturn();
                }
                int status = result.getResponse().getStatus();
                if (result.getResolvedException() != null && security(result.getResolvedException())) {
                    return new Sent(new Result(Outcome.DENIED, sent + " -> " + status + " "
                            + root(result.getResolvedException())));
                }
                String location = result.getResponse().getHeader("Location");
                HttpSession session = result.getRequest().getSession(false);
                boolean startsAuthentication = session != null && session.getAttribute(SAVED_REQUEST) != null;
                return new Sent(new Result(status(status, result.getHandler() == null, startsAuthentication,
                        location), sent + " -> " + status + (location == null ? "" : " " + location),
                        result.getResponse().getContentAsString(StandardCharsets.UTF_8),
                        result.getResponse().getContentType()), status, result.getResolvedException());
            } catch (Exception | AssertionError e) {
                return new Sent(new Result(security(e) ? Outcome.DENIED : Outcome.ERROR, sent + " -> " + root(e)));
            } finally {
                TestSecurityContextHolder.clearContext();
            }
        }

        private static void params(Expectation endpoint, MockHttpServletRequestBuilder request) {
            for (String part : endpoint.params().isEmpty() ? new String[0] : endpoint.params().split("&")) {
                // Header (name:value) and negated (!name) conditions aren't sent.
                if (part.startsWith("!") || part.contains(":")) {
                    continue;
                }
                int equals = part.indexOf('=');
                if (equals > 0) {
                    request.param(part.substring(0, equals), part.substring(equals + 1));
                } else {
                    request.param(part, "1");
                }
            }
        }
    }

    /**
     * WebTestClient bound to the application context, with Spring Security's WebFilterChainProxy when there is one.
     */
    private record Reactive(WebTestClient client) implements Client {

        @Override
        public Result send(Expectation endpoint, Callers.Probe probe) {
            String method = method(endpoint);
            String path = fill(endpoint.route());
            WebTestClient caller = client;
            if (probe.caller() != null) {
                caller = caller.mutateWith(mockAuthentication(probe.caller()));
            }
            if (!SAFE.contains(method)) {
                caller = caller.mutateWith(org.springframework.security.test.web.reactive.server
                        .SecurityMockServerConfigurers.csrf());
            }
            String sent = method + " " + path;
            try {
                EntityExchangeResult<byte[]> result = caller.method(HttpMethod.valueOf(method))
                        .uri(uri -> {
                            uri.path(path);
                            for (String part : endpoint.params().isEmpty() ? new String[0]
                                    : endpoint.params().split("&")) {
                                int equals = part.indexOf('=');
                                if (!part.startsWith("!") && !part.contains(":")) {
                                    uri.queryParam(equals > 0 ? part.substring(0, equals) : part,
                                            equals > 0 ? part.substring(equals + 1) : "1");
                                }
                            }
                            return uri.build();
                        })
                        .exchange().expectBody().returnResult();
                int status = result.getStatus().value();
                var location = result.getResponseHeaders().getLocation();
                MediaType type = result.getResponseHeaders().getContentType();
                byte[] body = result.getResponseBody();
                return new Result(status(status, false, false, location == null ? null : location.toString()),
                        sent + " -> " + status + (location == null ? "" : " " + location),
                        body == null ? null : new String(body, StandardCharsets.UTF_8),
                        type == null ? null : type.toString());
            } catch (Exception | AssertionError e) {
                return new Result(security(e) ? Outcome.DENIED : Outcome.ERROR, sent + " -> " + root(e));
            }
        }
    }
}
