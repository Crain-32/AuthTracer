package dev.crain.authtracer.link;

import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * One span, in the shape of the Zipkin v2 API.
 *
 * @param kind {@code SERVER}, {@code CLIENT}, {@code PRODUCER} (a message sent), {@code CONSUMER} (a message
 *        received), or {@code null} for local spans
 */
@Supports(Feature.TRACE_OBSERVATIONS)
public record TraceSpan(String traceId, String id, String parentId, String kind, String name, String service,
        long timestamp, Map<String, String> tags) {

    public Optional<String> tag(String... names) {
        for (String name : names) {
            String value = tags.get(name);
            if (value != null && !value.isBlank()) {
                return Optional.of(value);
            }
        }
        return Optional.empty();
    }

    public boolean isServer() {
        return "SERVER".equals(kind);
    }

    public boolean isClient() {
        return "CLIENT".equals(kind);
    }

    public boolean isProducer() {
        return "PRODUCER".equals(kind);
    }

    public boolean isConsumer() {
        return "CONSUMER".equals(kind);
    }
}
