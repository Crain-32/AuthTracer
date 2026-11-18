package dev.crain.authtracer.diff;

import java.util.ArrayList;
import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.Requirement;

/**
 * Small hand-built graphs: endpoints returning {@code app.View}, whose fields come from {@code app.Account}.
 */
final class TestGraphs {

    private final String service;
    private final List<Node> nodes = new ArrayList<>();
    private final List<Edge> edges = new ArrayList<>();
    private final List<Flow> flows = new ArrayList<>();

    private TestGraphs(String service) {
        this.service = service;
    }

    static TestGraphs service(String service) {
        return new TestGraphs(service);
    }

    /**
     * An endpoint returning a View built from Account, with request-level checks and optionally field checks.
     */
    TestGraphs endpoint(String method, String route, List<Requirement> checks, List<String> exposedAccountFields,
            List<FieldCheck> fieldChecks) {
        Ingress ingress = Ingress.of(method, route, CodeRef.ofMethod("app.Controller", route))
                .withResponse(new Payload("app.View", false));
        nodes.add(ingress);
        String previous = ingress.id();
        int order = 1;
        for (int i = 0; i < checks.size(); i++) {
            // By method too: a route's GET and HEAD may ask different things.
            AuthorizationLocation location = location("location:METHOD:" + (method.equals("GET") ? "" : method + " ")
                    + route + ":" + i,
                    AuthorizationLocation.Scope.METHOD, checks.get(i), null, "app.Service");
            add(location);
            edges.add(Edge.local(ingress.id(), previous, location.id(), order++, List.of()));
            previous = location.id();
        }
        for (FieldCheck check : fieldChecks) {
            AuthorizationLocation location = location("location:FIELD:app.Account#" + check.field(),
                    AuthorizationLocation.Scope.FIELD, check.requirement(), check.field(), "app.Account");
            add(location);
            edges.add(Edge.local(ingress.id(), previous, location.id(), order++, List.of()));
            previous = location.id();
        }
        for (String field : exposedAccountFields) {
            add(Field.of("app.View", field, field, "java.lang.String"));
            add(Field.of("app.Account", field, field, "java.lang.String"));
            flows.add(Flow.local(ingress.id(), Field.id("app.Account", field), Field.id("app.View", field),
                    FieldSource.DIRECT));
        }
        return this;
    }

    record FieldCheck(String field, Requirement requirement) {
    }

    ApplicationGraph build(String revision) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, revision, 8080, AuthoritySource.UNKNOWN,
                new ArrayList<>(nodes), edges, flows, List.of(), List.of());
    }

    private void add(Node node) {
        if (nodes.stream().noneMatch(existing -> existing.id().equals(node.id()))) {
            nodes.add(node);
        }
    }

    private static AuthorizationLocation location(String id, AuthorizationLocation.Scope scope,
            Requirement requirement, String field, String className) {
        return new AuthorizationLocation(id, "@PreAuthorize", scope, AuthorizationLocation.Phase.PRE, requirement,
                CodeRef.ofMethod(className, "m()"), field, null, AuthorizationLocation.Denial.THROW, true);
    }
}
