package dev.crain.authtracer.scan;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Extension point: one framework's "right approach" to authorization (Spring Security first).
 * A module recognizes entry points, Authorization Locations and egress for its framework and adds them to the graph.
 */
@Supports(Feature.APPLICATION_GRAPH)
public interface FrameworkModule {

    /**
     * Whether the scanned application uses this framework at all.
     */
    boolean applies(ScanContext context);

    void scan(ScanContext context, GraphBuilder graph);
}
