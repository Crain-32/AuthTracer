package dev.crain.authtracer.graph;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * One service's AuthZ graph at one revision, as produced by a scan.
 * Lists are kept sorted so two graphs of the same code serialize identically.
 *
 * @param port the port the service listens on, when its configuration says, for matching other services' egress
 * @param provided the Provided facts applied to this scan
 * @param additionalPorts other ports it also listens on, e.g. a second connector its code adds
 * @param issuer what it issues tokens with, when it is an authorization server
 */
@Supports(Feature.APPLICATION_GRAPH)
public record ApplicationGraph(
        int schemaVersion,
        String service,
        String revision,
        Integer port,
        AuthoritySource authoritySource,
        List<Node> nodes,
        List<Edge> edges,
        List<Flow> flows,
        List<ProvidedFact> provided,
        List<Finding> findings,
        @JsonInclude(JsonInclude.Include.NON_EMPTY) List<Integer> additionalPorts,
        @JsonInclude(JsonInclude.Include.NON_NULL) Issuer issuer) {

    public static final int SCHEMA_VERSION = 1;

    public ApplicationGraph(int schemaVersion, String service, String revision, Integer port,
            AuthoritySource authoritySource, List<Node> nodes, List<Edge> edges, List<Flow> flows,
            List<ProvidedFact> provided, List<Finding> findings) {
        this(schemaVersion, service, revision, port, authoritySource, nodes, edges, flows, provided, findings,
                List.of());
    }

    public ApplicationGraph(int schemaVersion, String service, String revision, Integer port,
            AuthoritySource authoritySource, List<Node> nodes, List<Edge> edges, List<Flow> flows,
            List<ProvidedFact> provided, List<Finding> findings, List<Integer> additionalPorts) {
        this(schemaVersion, service, revision, port, authoritySource, nodes, edges, flows, provided, findings,
                additionalPorts, null);
    }

    public ApplicationGraph {
        additionalPorts = additionalPorts == null ? List.of() : List.copyOf(additionalPorts);
        provided = provided == null ? List.of() : List.copyOf(provided);
        // Tolerant on read: a file that leaves a list out has none.
        nodes = nodes == null ? List.of() : nodes.stream().sorted(Comparator.comparing(Node::id)).toList();
        edges = edges == null ? List.of() : edges.stream().sorted(Edge.ORDER).toList();
        flows = flows == null ? List.of() : flows.stream().distinct().sorted(Flow.ORDER).toList();
        findings = findings == null ? List.of() : findings.stream().sorted(Finding.ORDER).toList();
    }

    public <T extends Node> List<T> nodes(Class<T> type) {
        return nodes.stream().filter(type::isInstance).map(type::cast).toList();
    }

    public Optional<Node> node(String id) {
        return nodes.stream().filter(node -> node.id().equals(id)).findFirst();
    }

    /**
     * The ordered steps of one Ingress's request path.
     */
    @Supports(Feature.CALL_PATHS)
    public List<Edge> path(String ingressId) {
        return edges.stream().filter(edge -> ingressId.equals(edge.path())).toList();
    }

    /**
     * The flows that build one Ingress's response.
     */
    @Supports(Feature.FIELD_LINEAGE)
    public List<Flow> flows(String ingressId) {
        return flows.stream().filter(flow -> ingressId.equals(flow.path())).toList();
    }
}
