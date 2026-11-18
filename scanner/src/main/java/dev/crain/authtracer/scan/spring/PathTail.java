package dev.crain.authtracer.scan.spring;

import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.GraphBuilder;

/**
 * The last node on a request path so far, and the next edge's order: where more steps are appended.
 */
@Supports(Feature.CALL_PATHS)
record PathTail(String node, int order) {

    static PathTail start(String ingress) {
        return new PathTail(ingress, 1);
    }

    PathTail append(GraphBuilder graph, String path, List<CallTraversal.Step> steps) {
        String previous = node;
        int next = order;
        for (CallTraversal.Step step : steps) {
            graph.edge(Edge.local(path, previous, step.nodeId(), next++, step.via())
                    .asConditional(step.conditional()));
            previous = step.nodeId();
        }
        return new PathTail(previous, next);
    }
}
