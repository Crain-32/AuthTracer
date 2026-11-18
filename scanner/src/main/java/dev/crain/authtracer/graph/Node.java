package dev.crain.authtracer.graph;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

@Supports(Feature.APPLICATION_GRAPH)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = Ingress.class, name = "ingress"),
        @JsonSubTypes.Type(value = Egress.class, name = "egress"),
        @JsonSubTypes.Type(value = AuthorizationLocation.class, name = "location"),
        @JsonSubTypes.Type(value = Field.class, name = "field"),
        @JsonSubTypes.Type(value = Opaque.class, name = "opaque")
})
public sealed interface Node permits Ingress, Egress, AuthorizationLocation, Field, Opaque {

    /**
     * Stable across scans of unchanged code, so graphs from different commits can be diffed by id.
     */
    String id();
}
