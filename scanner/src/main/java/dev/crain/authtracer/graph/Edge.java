package dev.crain.authtracer.graph;

import java.util.Comparator;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * A Callpath between two nodes.
 *
 * @param path the Ingress whose request path this edge is part of; a node such as a field check can sit on several
 *        paths, so each path's chain is followed by this id. {@code null} for edges shared by all paths.
 * @param order position of {@code to} along {@code path} (1 = first step), which is the relative timing of checks
 * @param via the methods between the path's entry point and {@code to}, outermost first
 * @param bidirectional data flows both ways, e.g. a request out and a response back
 * @param conditional {@code to} is reached only on some of the ways the code returns (decision 0027), so it doesn't
 *        constrain the whole path
 */
@Supports({Feature.CALL_PATHS, Feature.SYSTEM_GRAPH, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Edge(String from, String to, Kind kind, String path, int order, List<String> via,
        boolean bidirectional, @JsonInclude(JsonInclude.Include.NON_DEFAULT) boolean conditional) {

    static final Comparator<Edge> ORDER = Comparator.comparing((Edge edge) -> String.valueOf(edge.path()))
            .thenComparingInt(Edge::order)
            .thenComparing(Edge::from)
            .thenComparing(Edge::to);

    public enum Kind {
        /** In-process call path. */
        LOCAL,
        /** Cross-service call confirmed by a trace. */
        NETWORK_OBSERVED,
        /** Cross-service call matched statically, not yet seen in a trace. */
        NETWORK_INFERRED
    }

    public Edge {
        via = via == null ? List.of() : List.copyOf(via);
    }

    public Edge(String from, String to, Kind kind, String path, int order, List<String> via, boolean bidirectional) {
        this(from, to, kind, path, order, via, bidirectional, false);
    }

    public static Edge local(String path, String from, String to, int order, List<String> via) {
        return new Edge(from, to, Kind.LOCAL, path, order, via, false);
    }

    public Edge asConditional(boolean conditional) {
        return new Edge(from, to, kind, path, order, via, bidirectional, conditional);
    }
}
