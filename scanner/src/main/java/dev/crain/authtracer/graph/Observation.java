package dev.crain.authtracer.graph;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * What traces showed for a node or link.
 *
 * @param subject a qualified location id, or {@code from -> to} for a link
 * @param count how many times it was seen
 * @param granted for a location, how many of those evaluations granted access
 * @param denied for a location, how many denied it
 */
@Supports({Feature.TRACE_OBSERVATIONS, Feature.SYSTEM_GRAPH})
public record Observation(String subject, Kind kind, long count, long granted, long denied) {

    public enum Kind {
        LOCATION, LINK
    }

    public static String linkSubject(String from, String to) {
        return from + " -> " + to;
    }
}
