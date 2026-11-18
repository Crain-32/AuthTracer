package dev.crain.authtracer.graph;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * A point on a request path the static analysis can't see past, e.g. reflection. What runs after it is unknown;
 * this is where the (post-MVP) agentic fallback attaches.
 */
@Supports({Feature.FINDING_OPAQUE_CALLPATH, Feature.APPLICATION_GRAPH})
public record Opaque(String id, String reason, CodeRef site) implements Node {

    public static Opaque of(String reason, CodeRef site) {
        return new Opaque("opaque:" + site.key() + ":" + site.line(), reason, site);
    }
}
