package dev.crain.authtracer.link;

import java.util.Collection;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Where traces come from: a trace store (Zipkin first) or a saved file. Adapters for other stores implement this.
 */
@Supports(Feature.TRACE_OBSERVATIONS)
public interface TraceSource {

    /**
     * Traces that involve any of the given services; each trace is its list of spans.
     */
    List<List<TraceSpan>> traces(Collection<String> services);
}
