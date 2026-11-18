package dev.crain.authtracer.scan;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Issuer;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.ProvidedFact;

@Supports(Feature.APPLICATION_GRAPH)
public final class GraphBuilder {

    private final String service;
    private final String revision;
    private final Map<String, Node> nodes = new LinkedHashMap<>();
    private final List<Edge> edges = new ArrayList<>();
    private final Set<Flow> flows = new LinkedHashSet<>();
    private final Set<Finding> findings = new LinkedHashSet<>();
    private final Map<String, Split> splits = new LinkedHashMap<>();
    private AuthoritySource authoritySource = AuthoritySource.UNKNOWN;
    private Integer port;
    private final Set<Integer> additionalPorts = new java.util.TreeSet<>();
    private List<ProvidedFact> provided = List.of();
    private Issuer issuer;

    public GraphBuilder(String service, String revision) {
        this.service = service;
        this.revision = revision;
    }

    /**
     * Adds the node unless one with the same id exists; returns the node kept.
     */
    @SuppressWarnings("unchecked")
    public <T extends Node> T node(T node) {
        return (T) nodes.computeIfAbsent(node.id(), id -> node);
    }

    /**
     * What a Split location (decision 0027) is made of: it asks for any one of the alternatives, each the checks it
     * lists, together.
     *
     * @param combined whether an alternative's {@code permitAll} checks drop out and the others count once, as one
     *        way in asks for them
     */
    @Supports({Feature.REQUEST_RULES, Feature.CALL_PATHS})
    public record Split(List<List<String>> alternatives, boolean combined) {

        /**
         * Alternatives of one check each.
         */
        public static Split of(List<String> locationIds) {
            return new Split(locationIds.stream().map(List::of).toList(), false);
        }
    }

    /**
     * Adds a Split location and records its parts, so that a pass that changes their requirements can rebuild it.
     */
    @Supports({Feature.REQUEST_RULES, Feature.CALL_PATHS})
    public AuthorizationLocation split(AuthorizationLocation location, Split parts) {
        AuthorizationLocation kept = node(location);
        splits.putIfAbsent(kept.id(), parts);
        return kept;
    }

    /**
     * The Split locations by id, each made after its parts (so the innermost come first).
     */
    @Supports({Feature.REQUEST_RULES, Feature.CALL_PATHS})
    public Map<String, Split> splits() {
        return Collections.unmodifiableMap(splits);
    }

    public Optional<Node> find(String id) {
        return Optional.ofNullable(nodes.get(id));
    }

    /**
     * How far the graph has got: what {@link #rollback} goes back to.
     */
    public record Mark(int nodes, int findings, int splits) {
    }

    public Mark mark() {
        return new Mark(nodes.size(), findings.size(), splits.size());
    }

    /**
     * Drops the nodes, findings and Split parts added since the mark: what a question asked of the rules (which check
     * would this request get?) added, when its answer isn't kept. Nodes replaced since keep their place and their
     * new value.
     */
    public void rollback(Mark mark) {
        dropAfter(nodes.keySet(), mark.nodes());
        dropAfter(findings, mark.findings());
        dropAfter(splits.keySet(), mark.splits());
    }

    private static void dropAfter(Collection<?> ordered, int kept) {
        java.util.Iterator<?> each = ordered.iterator();
        for (int i = 0; each.hasNext(); i++) {
            each.next();
            if (i >= kept) {
                each.remove();
            }
        }
    }

    public void edge(Edge edge) {
        edges.add(edge);
    }

    /**
     * Replaces a node with an enriched version of itself (same id).
     */
    public <T extends Node> T replace(T node) {
        nodes.put(node.id(), node);
        return node;
    }

    @Supports(Feature.FIELD_LINEAGE)
    public void flow(Flow flow) {
        flows.add(flow);
    }

    public void finding(Finding finding) {
        findings.add(finding);
    }

    /**
     * Each finding as the function renames it, in the same order; two that become the same are one.
     */
    public void renameFindings(java.util.function.UnaryOperator<Finding> rename) {
        List<Finding> renamed = findings.stream().map(rename).toList();
        findings.clear();
        findings.addAll(renamed);
    }

    @Supports(Feature.AUTHORITY_SOURCE)
    public void authoritySource(AuthoritySource authoritySource) {
        this.authoritySource = authoritySource;
    }

    @Supports(Feature.SYSTEM_GRAPH)
    public void port(Integer port) {
        this.port = port;
    }

    @Supports({Feature.FINDING_TOKEN_REJECTED, Feature.FINDING_ALWAYS_DENIED})
    public void issuer(Issuer issuer) {
        this.issuer = issuer;
    }

    @Supports(Feature.SYSTEM_GRAPH)
    public void additionalPort(int port) {
        additionalPorts.add(port);
    }

    @Supports(Feature.PROVIDED_FACTS)
    public void provided(List<ProvidedFact> provided) {
        this.provided = List.copyOf(provided);
    }

    public Collection<Node> nodes() {
        return nodes.values();
    }

    /**
     * The edges of one Ingress's path, so far.
     */
    public List<Edge> path(String ingressId) {
        return edges.stream().filter(edge -> ingressId.equals(edge.path())).toList();
    }

    public ApplicationGraph build() {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, revision, port, authoritySource,
                new ArrayList<>(nodes.values()), edges, new ArrayList<>(flows), provided, new ArrayList<>(findings),
                List.copyOf(additionalPorts), issuer);
    }
}
