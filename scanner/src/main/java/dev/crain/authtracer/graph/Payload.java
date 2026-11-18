package dev.crain.authtracer.graph;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * A request or response body type.
 *
 * @param many the body is a collection of {@code type}
 * @param views the {@code @JsonView} the handler writes it with, and the views that one extends: only fields in one of
 *        them are written; empty for no view
 */
@Supports({Feature.RESPONSE_FIELDS, Feature.APPLICATION_GRAPH})
public record Payload(String type, boolean many, @JsonInclude(JsonInclude.Include.NON_EMPTY) List<String> views) {

    public Payload {
        views = views == null ? List.of() : List.copyOf(views);
    }

    public Payload(String type, boolean many) {
        this(type, many, List.of());
    }

    public Payload withViews(List<String> views) {
        return new Payload(type, many, views);
    }
}
