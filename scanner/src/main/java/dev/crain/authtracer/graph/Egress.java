package dev.crain.authtracer.graph;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Where a request leaves the service, e.g. a RestClient call site.
 *
 * @param baseUrl the resolved base URL when it is statically known, otherwise {@code null}
 * @param baseUrlExpression the unresolved form, e.g. {@code ${employee-service.base-url}}, when it came from configuration
 * @param response the type the response body is read into, when it is known
 * @param credentials what the call authenticates with; {@code null} in graphs scanned before it was recorded
 * @param credentialsVia the code that showed it, e.g. {@code ServletBearerExchangeFilterFunction}
 * @param query the URL's query string when it is a constant ({@code use_case=delegation}), which picks between
 *        endpoints told apart by their params; {@code null} when there is none or it isn't known
 * @param request the type of what the call sends, when it is a message of an application type (decision 0090): the
 *        Flows with this Egress as their path fill its fields; {@code null} otherwise
 * @param registration the OAuth2 client registration whose token it sends, when AuthTracer reads which one and what
 *        the service's properties declare of it (decision 0075 amended); {@code null} otherwise
 */
@Supports({Feature.SERVICE_CALLS, Feature.MESSAGE_SENDS, Feature.INFRASTRUCTURE_CALLS, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Egress(String id, String client, String httpMethod, String uriTemplate, String baseUrl,
        String baseUrlExpression, CodeRef callSite, Payload response, Credentials credentials, String credentialsVia,
        String query, Payload request, Registration registration) implements Node {

    /**
     * The target of a call AuthTracer recognises but can't read, its path, route, topic or operation (decision 0082):
     * the call is shown, and it links to nothing.
     */
    public static final String UNKNOWN_TARGET = "?";

    public Egress(String id, String client, String httpMethod, String uriTemplate, String baseUrl,
            String baseUrlExpression, CodeRef callSite, Payload response, Credentials credentials,
            String credentialsVia, String query, Payload request) {
        this(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response, credentials,
                credentialsVia, query, request, null);
    }

    public Egress(String id, String client, String httpMethod, String uriTemplate, String baseUrl,
            String baseUrlExpression, CodeRef callSite, Payload response, Credentials credentials,
            String credentialsVia, String query) {
        this(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response, credentials,
                credentialsVia, query, null);
    }

    public Egress(String id, String client, String httpMethod, String uriTemplate, String baseUrl,
            String baseUrlExpression, CodeRef callSite, Payload response, Credentials credentials,
            String credentialsVia) {
        this(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response, credentials,
                credentialsVia, null);
    }

    public static Egress of(String client, String httpMethod, String uriTemplate, String baseUrl,
            String baseUrlExpression, CodeRef callSite, Payload response) {
        String id = "egress:" + callSite.key() + " " + httpMethod + " " + uriTemplate;
        return new Egress(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response, null,
                null);
    }

    @Supports(Feature.CALL_CREDENTIALS)
    public Egress withCredentials(Credentials credentials, String via) {
        return new Egress(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response,
                credentials, via, query, request, registration);
    }

    /**
     * The same call, with the OAuth2 client registration whose token it sends.
     */
    @Supports(Feature.CALL_CREDENTIALS)
    public Egress withRegistration(Registration registration) {
        return new Egress(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response,
                credentials, credentialsVia, query, request, registration);
    }

    /**
     * The same call, at another site: its id names that site instead.
     */
    public Egress withCallSite(CodeRef site) {
        String prefix = "egress:" + callSite.key();
        String moved = id.startsWith(prefix) ? "egress:" + site.key() + id.substring(prefix.length()) : id;
        return new Egress(moved, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, site, response,
                credentials, credentialsVia, query, request, registration);
    }

    public Egress withQuery(String query) {
        return new Egress(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response,
                credentials, credentialsVia, query == null || query.isEmpty() ? null : query, request, registration);
    }

    @Supports(Feature.FIELD_LINEAGE)
    public Egress withRequest(Payload request) {
        return new Egress(id, client, httpMethod, uriTemplate, baseUrl, baseUrlExpression, callSite, response,
                credentials, credentialsVia, query, request, registration);
    }
}
