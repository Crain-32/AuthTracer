package dev.crain.authtracer.scan.flow;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.flow.Shape.Composite;
import dev.crain.authtracer.scan.flow.Shape.Leaf;
import dev.crain.authtracer.scan.flow.TypeProperties.Property;

/**
 * Turns the shape of a response into Field nodes and the Flows that fill them.
 */
@Supports({Feature.RESPONSE_FIELDS, Feature.FIELD_LINEAGE})
public final class ResponseFields {

    private static final String DENIED = "(denied)";

    /**
     * The types Jackson 3.1 takes {@code isX()} for ({@code DefaultAccessorNamingStrategy._booleanType}).
     */
    private static final Set<String> BOOLEANS = Set.of("boolean", "java.lang.Boolean",
            "java.util.concurrent.atomic.AtomicBoolean");

    private final GraphBuilder graph;
    private final TypeProperties properties;

    public ResponseFields(GraphBuilder graph, TypeProperties properties) {
        this.graph = graph;
        this.properties = properties;
    }

    /**
     * @param path the Ingress whose response this is
     */
    public void expose(String path, String type, Shape shape) {
        flatten(path, type, shape, new HashSet<>());
    }

    private void flatten(String path, String type, Shape shape, Set<String> enclosing) {
        if (!properties.isApplicationType(type) || !enclosing.add(type)) {
            return;
        }
        properties.writtenOtherwise(type).ifPresent(why -> graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG,
                type + " is in a response, and " + why + ": its fields in the graph are its properties, which may"
                        + " not be what Jackson writes", CodeRef.ofClass(type))));
        Map<String, Shape> components = shape instanceof Composite composite && composite.type().equals(type)
                ? composite.components() : Map.of();
        for (Property property : properties.of(type)) {
            if (property.accessor().startsWith("is") && !property.accessor().equals(property.name())
                    && !BOOLEANS.contains(property.type())) {
                // An isX() of anything else reads the field, but Jackson doesn't write it. A record's accessor is
                // its component's name (isbn()), which Jackson writes whatever it starts with.
                continue;
            }
            Field field = field(type, property);
            fill(path, field, components.get(property.name()), field.javaType(), enclosing);
        }
        enclosing.remove(type);
    }

    /**
     * A field a resolver adds to the type it resolves (GraphQL), or fills in place of the type's own property: what
     * its value flows from on this request path.
     *
     * @param shape what the resolver returns
     */
    @Supports(Feature.GRAPHQL_OPERATIONS)
    public void resolved(String path, String owner, String name, String javaType, Shape shape) {
        Field to = graph.node(properties.byName(owner, name)
                .map(property -> Field.of(owner, property.name(), property.jsonName(), property.type()))
                .orElse(Field.of(owner, name, name, javaType)));
        Set<String> enclosing = new HashSet<>(Set.of(owner));
        fill(path, to, shape, javaType, enclosing);
        if (!(shape instanceof Composite) && properties.isApplicationType(javaType)) {
            flatten(path, javaType, Shape.EMPTY, enclosing);
        }
    }

    /**
     * DENY-02 (decision 0076): when a check on the field denies, its denial handler writes a value it derives from
     * the field's in its place. That value is a field of its own beside the real one, {@code iban(denied)}, which
     * the denied callers get.
     *
     * @param fieldId the field the check guards
     */
    @Supports(Feature.FIELD_CHECKS)
    public void denied(String path, String fieldId) {
        Field real = ensureField(fieldId);
        Field masked = graph.node(Field.of(real.owner(), real.name() + DENIED, real.jsonName() + DENIED,
                real.javaType()).withViews(real.views()));
        graph.flow(Flow.local(path, real.id(), masked.id(), FieldSource.MASKED));
    }

    private void fill(String path, Field to, Shape shape, String type, Set<String> enclosing) {
        // A map of named arguments holds its values, whatever their names.
        Shape component = shape == null ? null : Shape.values(shape);
        if (component instanceof Composite nested) {
            for (String origin : Shape.fields(nested)) {
                flow(path, origin, to, FieldSource.COMPLEX);
            }
            flatten(path, nested.type(), nested, enclosing);
        }
        else if (component instanceof Leaf leaf) {
            for (String origin : leaf.fields()) {
                flow(path, origin, to, leaf.computed() ? FieldSource.COMPUTED : FieldSource.DIRECT);
            }
            // A collection or map of application objects read whole: its elements' fields are still in the response.
            if (type.endsWith("[]") || Field.isMap(type)) {
                flatten(path, Field.held(type), Shape.EMPTY, enclosing);
            }
        }
        else if (component == null && properties.isApplicationType(Field.held(type))) {
            flatten(path, Field.held(type), Shape.EMPTY, enclosing);
        }
    }

    private void flow(String path, String origin, Field to, FieldSource source) {
        if (origin.equals(to.id())) {
            return;
        }
        ensureField(origin);
        graph.flow(Flow.local(path, origin, to.id(), source));
    }

    private Field field(String owner, Property property) {
        return graph.node(Field.of(owner, property.name(), property.jsonName(), properties.heldType(owner, property))
                .withViews(property.views()));
    }

    private Field ensureField(String id) {
        String qualified = id.substring("field:".length());
        int dot = qualified.lastIndexOf('.');
        String owner = qualified.substring(0, dot);
        String name = qualified.substring(dot + 1);
        Property property = properties.byName(owner, name).orElse(new Property(name, name, "?", name));
        return field(owner, property);
    }
}
