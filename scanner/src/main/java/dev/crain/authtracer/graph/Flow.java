package dev.crain.authtracer.graph;

import java.util.Comparator;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Data moving from one field into another.
 *
 * @param path the Ingress whose response a {@link Kind#LOCAL} flow builds, or the message Egress whose payload it
 *        builds (decision 0090); for a {@link Kind#NETWORK} flow, the qualified Egress whose call carries the field
 *        from the called service, or whose message carries it to the listener
 * @param kind {@link Kind#LOCAL} inside the service, {@link Kind#NETWORK} across a call between services
 */
@Supports({Feature.FIELD_LINEAGE, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Flow(String path, String from, String to, FieldSource source, Kind kind) {

    static final Comparator<Flow> ORDER = Comparator.comparing((Flow flow) -> String.valueOf(flow.path()))
            .thenComparing(Flow::to)
            .thenComparing(Flow::from);

    public enum Kind {
        LOCAL, NETWORK
    }

    public static Flow local(String path, String from, String to, FieldSource source) {
        return new Flow(path, from, to, source, Kind.LOCAL);
    }
}
