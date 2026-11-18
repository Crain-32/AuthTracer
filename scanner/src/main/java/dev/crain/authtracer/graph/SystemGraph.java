package dev.crain.authtracer.graph;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Several services' graphs linked together: cross-service edges, the fields that travel over them, and what traces
 * showed at runtime. Ids in {@code links}, {@code flows} and {@code observations} are qualified as
 * {@code service/nodeId}.
 *
 * @param identities the identities traces showed, with what they were granted and what their requests needed
 */
@Supports(Feature.SYSTEM_GRAPH)
public record SystemGraph(
        int schemaVersion,
        List<ApplicationGraph> services,
        List<Edge> links,
        List<Flow> flows,
        List<Observation> observations,
        List<IdentityUsage> identities,
        List<Finding> findings) {

    public static final int SCHEMA_VERSION = 1;

    public SystemGraph {
        // Tolerant on read: a file that leaves a list out has none.
        services = services == null ? List.of()
                : services.stream().sorted(Comparator.comparing(ApplicationGraph::service)).toList();
        links = links == null ? List.of() : links.stream().distinct().sorted(Edge.ORDER).toList();
        flows = flows == null ? List.of() : flows.stream().distinct().sorted(Flow.ORDER).toList();
        observations = observations == null ? List.of()
                : observations.stream().sorted(Comparator.comparing(Observation::subject)).toList();
        identities = identities == null ? List.of() : identities.stream().sorted(IdentityUsage.ORDER).toList();
        findings = findings == null ? List.of() : findings.stream().distinct().sorted(Finding.ORDER).toList();
    }

    /**
     * One service on its own: nothing linked, nothing observed.
     */
    public static SystemGraph of(ApplicationGraph graph) {
        return new SystemGraph(SCHEMA_VERSION, List.of(graph), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    public static String qualify(String service, String nodeId) {
        return service + "/" + nodeId;
    }

    public static String serviceOf(String qualifiedId) {
        return qualifiedId.substring(0, qualifiedId.indexOf('/'));
    }

    public static String nodeOf(String qualifiedId) {
        return qualifiedId.substring(qualifiedId.indexOf('/') + 1);
    }

    public Optional<ApplicationGraph> service(String name) {
        return services.stream().filter(graph -> graph.service().equals(name)).findFirst();
    }

    public Optional<Node> node(String qualifiedId) {
        return service(serviceOf(qualifiedId)).flatMap(graph -> graph.node(nodeOf(qualifiedId)));
    }

    /**
     * The links leaving a qualified egress id.
     */
    public List<Edge> linksFrom(String qualifiedEgressId) {
        return links.stream().filter(link -> link.from().equals(qualifiedEgressId)).toList();
    }

    public Optional<Observation> observation(String subject) {
        return observations.stream().filter(observation -> observation.subject().equals(subject)).findFirst();
    }
}
