package dev.crain.authtracer.graph;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Where a request enters the service, e.g. a controller mapping.
 *
 * @param httpMethod {@code GET}, {@code POST}, ... or {@code *} when the mapping accepts any method
 * @param response the type of the response body, when it is known
 * @param params the request parameters the mapping requires ({@code use_case=delegation}), which tell apart handlers of
 *        one path; {@code null} for none. They are part of the id, not of the route the rules and the linker match.
 * @param request the type of what a message listener receives, when it is an application type (decision 0090);
 *        {@code null} otherwise
 * @param otherResponses what else it answers with: a STOMP topic several handlers send to gets each sender's type,
 *        {@code response} the first's
 */
@Supports(Feature.APPLICATION_GRAPH)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Ingress(String id, String httpMethod, String route, CodeRef handler, Payload response, String params,
        Payload request, @JsonInclude(JsonInclude.Include.NON_EMPTY) List<Payload> otherResponses) implements Node {

    public Ingress {
        otherResponses = otherResponses == null ? List.of() : List.copyOf(otherResponses);
    }

    public Ingress(String id, String httpMethod, String route, CodeRef handler, Payload response, String params,
            Payload request) {
        this(id, httpMethod, route, handler, response, params, request, List.of());
    }

    public Ingress(String id, String httpMethod, String route, CodeRef handler, Payload response, String params) {
        this(id, httpMethod, route, handler, response, params, null);
    }

    public Ingress(String id, String httpMethod, String route, CodeRef handler, Payload response) {
        this(id, httpMethod, route, handler, response, null);
    }

    public static Ingress of(String httpMethod, String route, CodeRef handler) {
        return new Ingress("ingress:" + httpMethod + " " + route, httpMethod, route, handler, null);
    }

    public Ingress withResponse(Payload response) {
        return new Ingress(id, httpMethod, route, handler, response, params, request, otherResponses);
    }

    /**
     * Another type it answers with, unless it is the response or among the others already.
     */
    @Supports(Feature.WEBSOCKET_MESSAGES)
    public Ingress withOtherResponse(Payload other) {
        if (other == null || other.equals(response) || otherResponses.contains(other)) {
            return this;
        }
        List<Payload> others = new ArrayList<>(otherResponses);
        others.add(other);
        return new Ingress(id, httpMethod, route, handler, response, params, request, others);
    }

    /**
     * The response, then the others.
     */
    public List<Payload> responses() {
        List<Payload> all = new ArrayList<>();
        if (response != null) {
            all.add(response);
        }
        all.addAll(otherResponses);
        return all;
    }

    @Supports(Feature.FIELD_LINEAGE)
    public Ingress withRequest(Payload request) {
        return new Ingress(id, httpMethod, route, handler, response, params, request, otherResponses);
    }

    /**
     * How the endpoint reads: {@code GET /user/messages}, with its params when it has any.
     */
    public String endpoint() {
        return httpMethod + " " + route + (params == null ? "" : "?" + params);
    }

    /**
     * The mapping's required parameters: {@code ingress:GET /user/messages?use_case=delegation}.
     */
    @Supports(Feature.HTTP_ENDPOINTS)
    public Ingress withParams(String params) {
        return params == null || params.isEmpty() ? this
                : new Ingress("ingress:" + httpMethod + " " + route + "?" + params, httpMethod, route, handler,
                        response, params, request, otherResponses);
    }

    /**
     * More required parameters after those it has, joined with {@code &}: {@code GET /users?version:2&handler=..}.
     */
    @Supports(Feature.HTTP_ENDPOINTS)
    public Ingress andParams(String more) {
        return withParams(params == null ? more : params + "&" + more);
    }

    /**
     * A Spring for GraphQL operation (decision 0029): {@code QUERY}, {@code MUTATION} or {@code SUBSCRIPTION}.
     */
    @Supports(Feature.GRAPHQL_OPERATIONS)
    public boolean graphQlOperation() {
        return GRAPHQL_OPERATIONS.contains(httpMethod);
    }

    private static final Set<String> GRAPHQL_OPERATIONS = Set.of("QUERY", "MUTATION", "SUBSCRIPTION");
}
