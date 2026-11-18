package dev.crain.authtracer.graph;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * How a field's value relates to the field it came from (see "FieldSource" in MVP.md).
 */
@Supports({Feature.FIELD_LINEAGE, Feature.APPLICATION_GRAPH})
public enum FieldSource {
    /** The same value, possibly reassigned or renamed. */
    DIRECT,
    /** A structure that nests one or more other fields. */
    COMPLEX,
    /** The outcome of a non-structural operation, e.g. concatenation, arithmetic, or a branch on the value. */
    COMPUTED,
    /**
     * What a field check's denial handler derives from the value and hands the callers the check denies, e.g. its
     * last four digits (DENY-02): the value's checks that answer instead of throwing don't stand in front of it.
     */
    MASKED
}
