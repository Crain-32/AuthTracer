package dev.crain.authtracer.api;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.provided.ProvidedFacts;

/**
 * What the server checks of a graph it is sent, before keeping it: a stored graph that linking or exposures can't
 * read would break them for every service until its own is published again.
 */
@Supports(Feature.GRAPH_SERVER)
final class GraphValidation {

    /**
     * The store's {@code service} column.
     */
    static final int MAX_SERVICE_LENGTH = 255;

    private GraphValidation() {
    }

    /**
     * @throws IllegalArgumentException naming what is wrong
     */
    static void check(SystemGraph system) {
        system.services().forEach(GraphValidation::check);
        for (Edge link : system.links()) {
            require(qualified(link.from()) && qualified(link.to()), "A link joins qualified ids (service/node): "
                    + link);
        }
        for (Flow flow : system.flows()) {
            require(qualified(flow.from()) && qualified(flow.to()), "A system flow joins qualified ids"
                    + " (service/node): " + flow);
        }
    }

    /**
     * A graph's service names it from then on, in ids ({@code service/nodeId}) and in the store, so it must be a name:
     * not blank, without {@code /}, and at most {@value #MAX_SERVICE_LENGTH} characters.
     *
     * @throws IllegalArgumentException naming what is wrong
     */
    static void check(ApplicationGraph graph) {
        String service = graph.service();
        require(service != null && !service.isBlank() && !service.contains("/")
                && service.length() <= MAX_SERVICE_LENGTH, "A graph's service must be a non-blank name without '/' of"
                        + " at most " + MAX_SERVICE_LENGTH + " characters, got: " + service);
        for (Node node : graph.nodes()) {
            require(node != null && node.id() != null, "Every node needs an id");
            switch (node) {
                case Ingress ingress -> require(ingress.httpMethod() != null && ingress.route() != null,
                        "Ingress " + ingress.id() + " needs a method and a route");
                case Egress egress -> require(egress.httpMethod() != null && egress.uriTemplate() != null,
                        "Egress " + egress.id() + " needs a method and a URI template");
                case Field field -> require(field.id().startsWith("field:")
                        && field.id().lastIndexOf('.') > "field:".length() && field.owner() != null
                        && field.jsonName() != null, "Field " + field.id() + " needs an id field:<class>.<property>,"
                                + " an owner and a JSON name");
                case AuthorizationLocation location -> require(location.scope() != null
                        && wellFormed(location.requirement()), "Location " + location.id() + " needs a scope and a"
                                + " requirement of a known kind");
                default -> {
                }
            }
        }
        for (Edge edge : graph.edges()) {
            require(edge.from() != null && edge.to() != null, "An edge needs both ends: " + edge);
        }
        for (ProvidedFact fact : graph.provided()) {
            ProvidedFacts.validate(fact);
        }
    }

    private static boolean wellFormed(Requirement requirement) {
        return requirement != null && requirement.kind() != null
                && requirement.operands().stream().allMatch(GraphValidation::wellFormed);
    }

    private static boolean qualified(String id) {
        return id != null && id.indexOf('/') > 0;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
