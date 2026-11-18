package dev.crain.authtracer.diff;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.diff.Clauses.Clause;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * What each endpoint exposes and what stands in front of it: for every Ingress, the endpoint itself and every
 * response field, with the field's root sources and the checks a caller passes to get it. Field-level checks count
 * only for the fields they guard, and only where they ran on the path; checks in called services count through the
 * links, when the call relays the caller's token (decision 0021): with other credentials they check the calling
 * service, not its caller. A nested field asks at least what its enclosing field does: it isn't sent without it.
 */
@Supports(Feature.EXPOSURES)
public final class Exposures {

    private static final Logger log = LoggerFactory.getLogger(Exposures.class);

    /**
     * A check on the way to an exposure.
     *
     * @param location the qualified Location id; for the checks of several endpoints one call may reach, the
     *        qualified id of the call
     */
    public record Step(String location, String mechanism, Requirement requirement) {
    }

    /**
     * @param field the JSON path of the response field, or empty for the endpoint itself
     * @param fieldId the qualified id of the response field, or empty for the endpoint itself
     * @param sources qualified ids of the fields the value ultimately comes from
     * @param labels sensitivity labels inherited from the sources (Provided facts)
     * @param labelledBy for each label, the qualified ids of the fields on the lineage that carry it
     * @param lineage the flows followed from the field back to its sources, with qualified ids
     */
    public record Exposure(String service, String ingress, String endpoint, String field, String fieldId,
            Set<String> sources, Set<String> labels, Map<String, Set<String>> labelledBy, List<Step> steps,
            List<Flow> lineage, List<Policies.Violation> violations) {

        public Exposure {
            labelledBy = Map.copyOf(labelledBy);
            violations = List.copyOf(violations);
        }

        Exposure withViolations(List<Policies.Violation> violations) {
            return new Exposure(service, ingress, endpoint, field, fieldId, sources, labels, labelledBy, steps,
                    lineage, violations);
        }

        public String key() {
            return key(service, endpoint, field);
        }

        /**
         * How the diff tells exposures apart: {@code employee-service GET /employees/{} ssn}. Route variables are unnamed, as
         * Spring matches them, so renaming {@code {id}} to {@code {employeeId}} compares the endpoint with itself; a
         * variable's pattern is kept ({@code {:\\d+}}, {@code {*}}), as two mappings that differ in it are two
         * endpoints.
         */
        public static String key(String service, String endpoint, String field) {
            return service + " " + unnamed(endpoint) + (field.isEmpty() ? "" : " " + field);
        }

        private static String unnamed(String endpoint) {
            StringBuilder key = new StringBuilder();
            int i = 0;
            while (i < endpoint.length()) {
                char c = endpoint.charAt(i);
                if (c != '{') {
                    key.append(c);
                    i++;
                    continue;
                }
                // To the matching brace: a pattern may have its own ({id:[0-9]{3}}).
                int depth = 0;
                int end = i;
                while (end < endpoint.length()) {
                    depth += endpoint.charAt(end) == '{' ? 1 : endpoint.charAt(end) == '}' ? -1 : 0;
                    if (depth == 0) {
                        break;
                    }
                    end++;
                }
                String variable = endpoint.substring(i + 1, Math.min(end, endpoint.length()));
                int colon = variable.indexOf(':');
                key.append('{').append(variable.startsWith("*") ? "*" : "")
                        .append(colon < 0 ? "" : variable.substring(colon)).append('}');
                i = end + 1;
            }
            return key.toString();
        }

        public Set<Clause> clauses() {
            return Clauses.of(steps.stream().map(Step::requirement).toList());
        }

        public String requirement() {
            return Clauses.describe(clauses());
        }
    }

    private static final int MAX_DEPTH = 6;
    /**
     * The checks of a path no caller is on: a message's sender, seen from what its listener received.
     */
    private static final PathChecks NO_CHECKS = new PathChecks(List.of(), Map.of(), List.of(), Set.of());

    private final SystemGraph system;
    /**
     * Whether a lineage was cut at the depth limit (said once).
     */
    private boolean cut;

    private Exposures(SystemGraph system) {
        this.system = system;
    }

    public static List<Exposure> of(SystemGraph system) {
        Exposures exposures = new Exposures(system);
        Policies policies = Policies.of(system);
        List<Exposure> all = new ArrayList<>();
        for (ApplicationGraph graph : system.services()) {
            for (Ingress ingress : graph.nodes(Ingress.class)) {
                exposures.of(graph, ingress).forEach(exposure -> all.add(exposure.withViolations(
                        policies.violations(exposure))));
            }
        }
        return all;
    }

    public static List<Exposure> of(ApplicationGraph graph) {
        return of(SystemGraph.of(graph));
    }

    private List<Exposure> of(ApplicationGraph graph, Ingress ingress) {
        PathChecks checks = checks(graph, ingress);
        String endpoint = ingress.endpoint();
        List<Exposure> exposures = new ArrayList<>();
        exposures.add(new Exposure(graph.service(), ingress.id(), endpoint, "", "", Set.of(), Set.of(), Map.of(),
                checks.requestSteps(), List.of(), List.of()));
        if (ingress.response() == null) {
            return exposures;
        }
        Map<String, Reached> fields = new LinkedHashMap<>();
        Set<String> left = notHandedOut(graph, ingress);
        // A topic several handlers send to: each sender's type.
        for (Payload response : ingress.responses()) {
            responseFields(graph, response.type(), "", null, ingress.graphQlOperation(), Set.copyOf(response.views()),
                    left, fields, new HashSet<>());
        }
        // Enclosing fields come first, so each field's own steps are known before those of the fields under it.
        Map<String, List<Step>> stepsByPath = new LinkedHashMap<>();
        fields.forEach((jsonPath, reached) -> {
            String fieldId = reached.fieldId();
            Trace trace = new Trace();
            trace(graph, ingress.id(), checks, fieldId, trace, 0, true);
            List<Step> steps = new ArrayList<>(checks.requestSteps());
            List<Step> enclosing = reached.parentPath() == null ? List.of()
                    : stepsByPath.getOrDefault(reached.parentPath(), List.of());
            enclosing.forEach(step -> addStep(steps, step));
            trace.steps.forEach(step -> addStep(steps, step));
            stepsByPath.put(jsonPath, steps);
            exposures.add(new Exposure(graph.service(), ingress.id(), endpoint, jsonPath,
                    SystemGraph.qualify(graph.service(), fieldId), trace.roots, trace.labels, trace.labelledBy, steps,
                    trace.flows, List.of()));
        });
        return exposures;
    }

    private static void addStep(List<Step> steps, Step step) {
        if (steps.stream().noneMatch(existing -> existing.location().equals(step.location()))) {
            steps.add(step);
        }
    }

    /**
     * A response field at one JSON path. A type nested twice ({@code address} and {@code billingAddress}) has its
     * fields at two paths, each under its own enclosing field.
     *
     * @param parentPath the JSON path of the enclosing field, {@code null} at the top of the response
     */
    private record Reached(String fieldId, String parentPath) {
    }

    /**
     * @param graphQl a GraphQL operation's response, which holds only the fields the schema declares (decision 0033)
     * @param views the handler's {@code @JsonView} and the views it extends: only fields in one of them are written
     *        (Jackson 3 leaves out fields with no view); empty for no view
     * @param fields the fields reached, by JSON path
     */
    private static void responseFields(ApplicationGraph graph, String type, String prefix, String parentPath,
            boolean graphQl, Set<String> views, Set<String> left, Map<String, Reached> fields, Set<String> enclosing) {
        if (!enclosing.add(type)) {
            return;
        }
        for (Field field : graph.nodes(Field.class)) {
            if (!field.owner().equals(type) || graphQl && Boolean.FALSE.equals(field.graphQl())
                    || !views.isEmpty() && field.views().stream().noneMatch(views::contains)
                    || left.contains(field.id())) {
                continue;
            }
            String path = prefix + field.jsonName();
            Reached held = fields.get(path);
            if (held != null && !held.fieldId().equals(field.id())) {
                // Another sender's type has a property of that name: this one is told apart by its type.
                path = path + " (" + field.owner().substring(field.owner().lastIndexOf('.') + 1) + ")";
            }
            fields.putIfAbsent(path, new Reached(field.id(), parentPath));
            // A collection's elements are written as an array, pets[].name; a map's values as an object's members,
            // pets.*.name.
            boolean many = field.javaType() != null && field.javaType().endsWith("[]");
            responseFields(graph, Field.held(field.javaType()), path + (many ? "[]." : Field.isMap(field.javaType())
                    ? ".*." : "."), path, graphQl, views, left, fields, enclosing);
        }
        enclosing.remove(type);
    }

    /**
     * The values denial handlers derive (DENY-02) that this endpoint's checks never hand out: those of the checks
     * serializing its response doesn't run.
     */
    @Supports(Feature.FIELD_CHECKS)
    private static Set<String> notHandedOut(ApplicationGraph graph, Ingress ingress) {
        Set<String> here = graph.flows(ingress.id()).stream().filter(flow -> flow.source() == FieldSource.MASKED)
                .map(Flow::to).collect(Collectors.toSet());
        return graph.flows().stream().filter(flow -> flow.source() == FieldSource.MASKED).map(Flow::to)
                .filter(id -> !here.contains(id)).collect(Collectors.toSet());
    }

    /**
     * The types a response holds: its own and those of its fields, nested.
     */
    private static Set<String> responseTypes(ApplicationGraph graph, String type) {
        Set<String> types = new HashSet<>();
        List<String> pending = new ArrayList<>(List.of(type));
        while (!pending.isEmpty()) {
            String next = pending.removeLast();
            if (types.add(next)) {
                graph.nodes(Field.class).stream().filter(field -> field.owner().equals(next))
                        .forEach(field -> pending.add(Field.held(field.javaType())));
            }
        }
        return types;
    }

    /**
     * The checks on one request path: request- and method-level ones apply to everything the endpoint returns;
     * field-level ones are kept by the field they guard.
     */
    private record PathChecks(List<Step> requestSteps, Map<String, List<Step>> fieldGuards, List<Egress> egress,
            Set<String> answering) {

        List<Step> guards(String fieldId) {
            return fieldGuards.getOrDefault(fieldId, List.of());
        }

        /**
         * Decision 0076: for what a denial handler derives from a value (a {@link FieldSource#MASKED} flow), the
         * field checks that answer a denied caller (a null, a masked value) don't stand in front of it, as it is what
         * they answer with.
         */
        @Supports(Feature.FIELD_CHECKS)
        PathChecks throwing() {
            Map<String, List<Step>> guards = new LinkedHashMap<>();
            fieldGuards.forEach((field, steps) -> guards.put(field, steps.stream()
                    .filter(step -> !answering.contains(step.location())).toList()));
            return new PathChecks(requestSteps, guards, egress, Set.of());
        }
    }

    private PathChecks checks(ApplicationGraph graph, Ingress ingress) {
        List<Step> requestSteps = new ArrayList<>();
        Map<String, List<Step>> fieldGuards = new LinkedHashMap<>();
        List<Egress> egress = new ArrayList<>();
        Set<String> answering = new HashSet<>();
        for (Edge edge : graph.path(ingress.id())) {
            Optional<Node> node = graph.node(edge.to());
            if (node.isPresent() && node.get() instanceof AuthorizationLocation location) {
                Step step = new Step(SystemGraph.qualify(graph.service(), location.id()), location.mechanism(),
                        location.requirement());
                if (edge.conditional()) {
                    // A check that runs on some branches only doesn't constrain the endpoint (decision 0027), nor
                    // the field it guards: on the other branches the value isn't the guarded one.
                    continue;
                }
                if (location.scope() == AuthorizationLocation.Scope.FIELD) {
                    List<Step> guards = fieldGuards.computeIfAbsent(location.guardedField(), id -> new ArrayList<>());
                    if (!guards.contains(step)) {
                        guards.add(step);
                    }
                    if (location.denial() != null
                            && location.denial().kind() != AuthorizationLocation.Denial.Kind.THROW) {
                        answering.add(step.location());
                    }
                }
                else {
                    requestSteps.add(step);
                }
            }
            else if (node.isPresent() && node.get() instanceof Egress call) {
                egress.add(call);
            }
        }
        return new PathChecks(requestSteps, fieldGuards, egress, answering);
    }

    /**
     * What following one field back to its roots found. A branch shares everything but its steps, for the checks
     * of one of several endpoints a call may reach.
     */
    private static final class Trace {
        final Set<String> roots;
        final Set<String> labels;
        final Map<String, Set<String>> labelledBy;
        final List<Flow> flows;
        /**
         * The fields followed, and of those the ones followed while checks counted, which covers following them
         * without.
         */
        final Set<String> visited;
        final Set<String> counted;
        final List<Step> steps = new ArrayList<>();

        Trace() {
            this(new LinkedHashSet<>(), new LinkedHashSet<>(), new LinkedHashMap<>(), new ArrayList<>(),
                    new HashSet<>(), new HashSet<>());
        }

        private Trace(Set<String> roots, Set<String> labels, Map<String, Set<String>> labelledBy, List<Flow> flows,
                Set<String> visited, Set<String> counted) {
            this.roots = roots;
            this.labels = labels;
            this.labelledBy = labelledBy;
            this.flows = flows;
            this.visited = visited;
            this.counted = counted;
        }

        /**
         * Its own fields visited, so one endpoint's lineage through a field doesn't hide another's.
         */
        Trace branch() {
            return new Trace(roots, labels, labelledBy, flows, new HashSet<>(visited), new HashSet<>(counted));
        }

        void flow(Flow flow) {
            if (!flows.contains(flow)) {
                flows.add(flow);
            }
        }

        void label(Field field, String qualified) {
            for (String label : field.labels()) {
                labels.add(label);
                labelledBy.computeIfAbsent(label, key -> new LinkedHashSet<>()).add(qualified);
            }
        }
    }

    /**
     * Follows a field back to its roots, collecting the field checks that ran on the way and, across links, the
     * checks of the called endpoint.
     *
     * @param path the Ingress whose response the flows followed build, or the message Egress whose payload they do
     * @param counts whether checks on this branch constrain the original caller: not past a call that doesn't relay
     *        the caller's token
     */
    private void trace(ApplicationGraph graph, String path, PathChecks checks, String fieldId, Trace trace,
            int depth, boolean counts) {
        String qualified = SystemGraph.qualify(graph.service(), fieldId);
        if (depth > MAX_DEPTH) {
            if (!cut) {
                cut = true;
                log.warn("A field's lineage is followed {} flows deep, no further: past {} in {}, its sources, labels"
                        + " and field checks aren't counted", MAX_DEPTH, fieldId, graph.service());
            }
            return;
        }
        // A visit that counts the checks covers one that doesn't, not the other way round.
        if (trace.counted.contains(qualified) || !(counts ? trace.counted : trace.visited).add(qualified)) {
            return;
        }
        Optional<Field> field = graph.node(fieldId).filter(Field.class::isInstance).map(Field.class::cast);
        field.ifPresent(node -> trace.label(node, qualified));
        if (counts) {
            trace.steps.addAll(checks.guards(fieldId));
        }
        if (field.isPresent() && field.get().declassified()) {
            // A Provided fact cut the inheritance here: the field is its own source. Its own checks still count.
            trace.roots.add(qualified);
            return;
        }
        List<Flow> incoming = graph.flows(path).stream().filter(flow -> flow.to().equals(fieldId)).toList();
        if (!incoming.isEmpty()) {
            incoming.forEach(flow -> {
                trace.flow(new Flow(SystemGraph.qualify(graph.service(), path),
                        SystemGraph.qualify(graph.service(), flow.from()), qualified, flow.source(), flow.kind()));
                trace(graph, path, flow.source() == FieldSource.MASKED ? checks.throwing() : checks, flow.from(),
                        trace, depth + 1, counts);
            });
            return;
        }
        if (!acrossLinks(graph, checks, fieldId, trace, depth, counts) && !acrossMessages(graph, fieldId, trace,
                depth) && !acrossWrites(graph, path, fieldId, trace, depth)) {
            trace.roots.add(qualified);
        }
    }

    /**
     * Decision 0098: a field nothing on this path fills, that a listener of this service writes from what it
     * received (LOCAL Flows on the listener's path, the Ingress with a request payload), holds what the listener
     * wrote, as fields are told apart by type: its lineage continues on the listener's path, and from there across
     * the message to its senders, and across the links of the calls the listener makes to what they returned. A
     * message carries no caller, so nothing on the listener's path, or past its calls, counts for this field's
     * readers; its sources and labels do. Returns whether it continued.
     */
    private boolean acrossWrites(ApplicationGraph graph, String path, String fieldId, Trace trace, int depth) {
        // A service's own flows are LOCAL, and none on this path fills the field.
        List<Flow> written = graph.flows().stream().filter(flow -> flow.to().equals(fieldId))
                .filter(flow -> graph.node(flow.path()).filter(Ingress.class::isInstance).map(Ingress.class::cast)
                        .map(Ingress::request).isPresent())
                .toList();
        for (Flow flow : written) {
            trace.flow(new Flow(SystemGraph.qualify(graph.service(), flow.path()),
                    SystemGraph.qualify(graph.service(), flow.from()), SystemGraph.qualify(graph.service(), fieldId),
                    flow.source(), flow.kind()));
            // The listener's calls, for what they returned; with nothing counting, none of its checks are added.
            Ingress listener = (Ingress) graph.node(flow.path()).orElseThrow();
            trace(graph, flow.path(), checks(graph, listener), flow.from(), trace, depth + 1, false);
        }
        return !written.isEmpty();
    }

    /**
     * Decision 0090: a field that holds what a listener of this service receives, with nothing on this path filling
     * it, holds what the senders sent: fields are told apart by type, and the listener's are those of its parameter.
     * It continues in each sender, where what the send's payload is built from fills it. A message carries no caller
     * (decision 0044), so the sender's checks don't count for this field's readers; its sources and labels do.
     * Returns whether it continued.
     */
    private boolean acrossMessages(ApplicationGraph graph, String fieldId, Trace trace, int depth) {
        String receivedId = SystemGraph.qualify(graph.service(), fieldId);
        boolean continued = false;
        for (Flow flow : system.flows()) {
            if (flow.kind() != Flow.Kind.NETWORK || !flow.to().equals(receivedId)
                    || !(system.node(flow.path()).orElse(null) instanceof Egress send) || send.request() == null) {
                continue;
            }
            Optional<ApplicationGraph> sender = system.service(SystemGraph.serviceOf(flow.from()));
            if (sender.isEmpty()) {
                continue;
            }
            continued = true;
            trace.flow(flow);
            trace(sender.get(), send.id(), NO_CHECKS, SystemGraph.nodeOf(flow.from()), trace, depth + 1, false);
        }
        return continued;
    }

    /**
     * A field received from an egress call continues in the called service; returns whether it did. The flows over
     * a link say which received fields, nested ones included, came from which of the callee's. When a call may reach
     * several endpoints (a base URL that names no one service), the value comes from one of them: the caller needs
     * what the weakest asks.
     */
    private boolean acrossLinks(ApplicationGraph graph, PathChecks checks, String fieldId, Trace trace, int depth,
            boolean counts) {
        String receivedId = SystemGraph.qualify(graph.service(), fieldId);
        boolean continued = false;
        for (Egress egress : checks.egress()) {
            if (egress.response() == null) {
                continue;
            }
            String egressId = SystemGraph.qualify(graph.service(), egress.id());
            boolean relayed = counts && Credentials.callerChecked(egress.credentials());
            Map<String, List<Step>> branches = new LinkedHashMap<>();
            for (Edge link : system.linksFrom(egressId)) {
                Optional<ApplicationGraph> callee = system.service(SystemGraph.serviceOf(link.to()));
                Optional<Node> remoteIngress = system.node(link.to());
                if (callee.isEmpty() || remoteIngress.isEmpty() || !(remoteIngress.get() instanceof Ingress remote)
                        || remote.response() == null) {
                    continue;
                }
                Set<String> types = responseTypes(callee.get(), remote.response().type());
                List<Flow> received = system.flows().stream()
                        .filter(flow -> egressId.equals(flow.path()) && flow.to().equals(receivedId))
                        .filter(flow -> SystemGraph.serviceOf(flow.from()).equals(callee.get().service())
                                && types.contains(Field.ownerOf(SystemGraph.nodeOf(flow.from()))))
                        .toList();
                if (received.isEmpty()) {
                    continue;
                }
                continued = true;
                PathChecks remoteChecks = checks(callee.get(), remote);
                Trace branch = trace.branch();
                if (relayed) {
                    remoteChecks.requestSteps().forEach(step -> addStep(branch.steps, step));
                }
                for (Flow flow : received) {
                    trace.flow(flow);
                    trace(callee.get(), remote.id(), remoteChecks, SystemGraph.nodeOf(flow.from()), branch, depth + 1,
                            relayed);
                }
                branches.put(callee.get().service() + " " + remote.endpoint(), branch.steps);
            }
            join(egressId, branches).forEach(step -> addStep(trace.steps, step));
        }
        return continued;
    }

    /**
     * The steps of the endpoints one call reaches: one endpoint's as they are; several endpoints' as one step that
     * any of them passes, unless they all ask the same.
     */
    private static List<Step> join(String egressId, Map<String, List<Step>> branches) {
        List<List<Step>> distinct = branches.values().stream().distinct().toList();
        if (distinct.size() < 2) {
            return distinct.isEmpty() ? List.of() : distinct.getFirst();
        }
        Requirement weakest = Requirement.or(branches.values().stream()
                .map(steps -> Requirement.and(steps.stream().map(Step::requirement).toList())).toList());
        return List.of(new Step(egressId, "the weakest of " + branches.keySet().stream()
                .collect(Collectors.joining(", ")), weakest));
    }
}
