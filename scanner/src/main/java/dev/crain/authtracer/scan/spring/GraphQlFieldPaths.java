package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.flow.ResponseFields;
import dev.crain.authtracer.scan.flow.ValueFlow;
import sootup.java.core.JavaSootMethod;

/**
 * Where GraphQL field resolvers join the operations' request paths.
 */
@Supports(Feature.GRAPHQL_OPERATIONS)
final class GraphQlFieldPaths {

    private GraphQlFieldPaths() {
    }

    /**
     * Decision 0030: a GraphQL field resolver runs when an operation's result holds an object of its type and the
     * query selects the field. Its checks guard that field only (a denial nulls the field and adds an error; the rest
     * of the result is returned), so they become one field check, after the role hierarchy widened them; its calls
     * to other services are on the operation's path; what it returns is the field's lineage.
     */
    static void append(GraphBuilder graph, List<RequestMappings.Mapping> operations,
            Map<GraphQlMappings.Resolver, List<CallTraversal.Step>> resolvers, Map<String, PathTail> tails,
            ResponseFields responseFields, ValueFlow valueFlow) {
        if (resolvers.isEmpty()) {
            return;
        }
        Map<GraphQlMappings.Resolver, List<CallTraversal.Step>> steps = new LinkedHashMap<>();
        resolvers.forEach((resolver, path) -> steps.put(resolver, resolverSteps(graph, resolver, path)));
        for (RequestMappings.Mapping operation : operations) {
            Ingress ingress = graph.find(operation.ingress().id()).map(Ingress.class::cast).orElseThrow();
            if (ingress.response() == null) {
                continue;
            }
            Set<String> types = resultTypes(graph, ingress.response().type(), resolvers.keySet());
            PathTail tail = tails.get(ingress.id());
            for (GraphQlMappings.Resolver resolver : resolvers.keySet()) {
                if (!types.contains(resolver.owner())) {
                    continue;
                }
                responseFields.resolved(ingress.id(), resolver.owner(), resolver.field(), resolver.javaType(),
                        valueFlow.returnShape(resolver.method()));
                tail = tail.append(graph, ingress.id(), steps.get(resolver));
            }
        }
    }

    /**
     * Decision 0033: marks the fields of the Java types the schema maps, found by following each operation's root
     * field type, and its fields' types, through the schema: in the schema or not.
     */
    static void markSchemaFields(GraphBuilder graph, GraphQlSchema schema, List<RequestMappings.Mapping> operations) {
        if (schema.isEmpty()) {
            return;
        }
        List<Field> fields = graph.nodes().stream().filter(Field.class::isInstance).map(Field.class::cast).toList();
        Map<String, String> mapped = new LinkedHashMap<>();
        for (RequestMappings.Mapping operation : operations) {
            Ingress ingress = operation.ingress();
            String root = schema.roots().get(ingress.httpMethod());
            String type = root == null ? null : schema.types().getOrDefault(root, Map.of()).get(ingress.route());
            graph.find(ingress.id()).map(Ingress.class::cast).map(Ingress::response)
                    .ifPresent(response -> map(response.type(), type, schema, fields, mapped));
        }
        for (Field field : fields) {
            String type = mapped.get(field.owner());
            if (type != null) {
                Map<String, String> declared = schema.types().get(type);
                graph.replace(field.withGraphQl(declared.containsKey(field.jsonName())
                        || declared.containsKey(field.name())));
            }
        }
    }

    private static void map(String javaType, String type, GraphQlSchema schema, List<Field> fields,
            Map<String, String> mapped) {
        if (type == null || !schema.types().containsKey(type) || mapped.putIfAbsent(javaType, type) != null) {
            return;
        }
        Map<String, String> declared = schema.types().get(type);
        for (Field field : fields) {
            if (field.owner().equals(javaType)) {
                String fieldType = declared.getOrDefault(field.jsonName(), declared.get(field.name()));
                map(Field.held(field.javaType()), fieldType, schema, fields, mapped);
            }
        }
    }

    /**
     * What a resolver adds to the paths it runs on: one field check for the checks every way through it passes, and
     * the calls it makes.
     */
    @Supports(Feature.FIELD_CHECKS)
    private static List<CallTraversal.Step> resolverSteps(GraphBuilder graph, GraphQlMappings.Resolver resolver,
            List<CallTraversal.Step> path) {
        List<CallTraversal.Step> steps = new ArrayList<>();
        List<Requirement> required = new ArrayList<>();
        for (CallTraversal.Step step : path) {
            Optional<Node> node = graph.find(step.nodeId());
            if (node.isPresent() && node.get() instanceof AuthorizationLocation location) {
                // Decision 0048: what fails on an @Async thread doesn't deny the field.
                if (location.scope() != AuthorizationLocation.Scope.FIELD && !step.conditional()
                        && !NoCaller.isOffThread(location.id()) && !required.contains(location.requirement())) {
                    required.add(location.requirement());
                }
            }
            else if (node.isPresent()) {
                steps.add(step);
            }
        }
        if (!required.isEmpty()) {
            JavaSootMethod method = resolver.method();
            AuthorizationLocation guard = graph.node(new AuthorizationLocation("location:FIELD:graphql:"
                    + MethodNames.key(method.getSignature()), "Resolver "
                    + method.getDeclaringClassType().getClassName() + "#" + method.getName(),
                    AuthorizationLocation.Scope.FIELD, AuthorizationLocation.Phase.PRE,
                    required.size() == 1 ? required.getFirst() : Requirement.and(required),
                    MethodNames.codeRef(method.getSignature()), resolver.field(), null,
                    new AuthorizationLocation.Denial(AuthorizationLocation.Denial.Kind.NULL, null), true,
                    resolver.owner()));
            steps.addFirst(new CallTraversal.Step(guard.id(), List.of(MethodNames.key(method.getSignature())),
                    false));
        }
        return steps;
    }

    /**
     * The types an operation's result can hold: its own, its fields' (the type's properties and the resolved fields),
     * transitively.
     */
    private static Set<String> resultTypes(GraphBuilder graph, String type, Set<GraphQlMappings.Resolver> resolvers) {
        Map<String, Set<String>> children = new HashMap<>();
        graph.nodes().stream().filter(Field.class::isInstance).map(Field.class::cast)
                .forEach(field -> children.computeIfAbsent(field.owner(), owner -> new HashSet<>())
                        .add(Field.held(field.javaType())));
        resolvers.forEach(resolver -> children.computeIfAbsent(resolver.owner(), owner -> new HashSet<>())
                .add(resolver.javaType()));
        Set<String> types = new LinkedHashSet<>(List.of(type));
        Deque<String> queue = new ArrayDeque<>(types);
        while (!queue.isEmpty()) {
            for (String child : children.getOrDefault(queue.removeFirst(), Set.of())) {
                if (types.add(child)) {
                    queue.add(child);
                }
            }
        }
        return types;
    }
}
