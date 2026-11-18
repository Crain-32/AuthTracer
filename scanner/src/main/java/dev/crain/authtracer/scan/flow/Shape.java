package dev.crain.authtracer.scan.flow;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.signatures.MethodSignature;

/**
 * What a value is made of, as far as fields go.
 */
@Supports(Feature.FIELD_LINEAGE)
public sealed interface Shape {

    Leaf EMPTY = new Leaf(Set.of(), Set.of(), false);

    /**
     * A plain value built from fields and/or the enclosing method's parameters.
     *
     * @param fields field ids the value comes from
     * @param params parameter indexes the value comes from, resolved at call sites
     * @param computed the value went through a non-structural operation
     */
    record Leaf(Set<String> fields, Set<Integer> params, boolean computed) implements Shape {

        public Leaf {
            fields = Set.copyOf(fields);
            params = Set.copyOf(params);
        }

        static Leaf field(String fieldId) {
            return new Leaf(Set.of(fieldId), Set.of(), false);
        }

        static Leaf param(int index) {
            return new Leaf(Set.of(), Set.of(index), false);
        }

        boolean isEmpty() {
            return fields.isEmpty() && params.isEmpty();
        }
    }

    /**
     * An object whose properties are known, e.g. a record built with {@code new}.
     */
    record Composite(String type, Map<String, Shape> components) implements Shape {

        public Composite {
            components = new LinkedHashMap<>(components);
        }
    }

    /**
     * A lambda or method reference to an application method.
     *
     * @param captured what it captures: a lambda's captured values come first among its parameters; a bound method
     *        reference ({@code client::find}) captures its receiver
     */
    record Function(MethodSignature target, List<Shape> captured) implements Shape {
    }

    /**
     * Lambdas or method references a value may be, one on each branch that assigns it: applying it applies each.
     */
    record Functions(List<Function> alternatives) implements Shape {

        public Functions {
            alternatives = List.copyOf(alternatives);
        }
    }

    /**
     * The functions a value may be: none for data.
     */
    static List<Function> functions(Shape shape) {
        return switch (shape) {
            case Function function -> List.of(function);
            case Functions functions -> functions.alternatives();
            default -> List.of();
        };
    }

    /**
     * A map of named arguments, Groovy's {@code [name: n, taxId: t]}: a {@link Composite} of this type whose
     * components are its keys.
     */
    String MAP = "java.util.Map";

    /**
     * A map of named arguments by its keys; empty for any other value.
     */
    static Optional<Map<String, Shape>> entries(Shape shape) {
        return shape instanceof Composite composite && composite.type().equals(MAP)
                ? Optional.of(composite.components()) : Optional.empty();
    }

    /**
     * What a value holds once its keys don't matter: a map of named arguments' values together, else the value.
     */
    static Shape values(Shape shape) {
        Optional<Map<String, Shape>> entries = entries(shape);
        if (entries.isEmpty()) {
            return shape;
        }
        Shape values = EMPTY;
        for (Shape value : entries.get().values()) {
            values = merge(values, value);
        }
        return values;
    }

    static Shape merge(Shape a, Shape b) {
        if (a == null || a instanceof Leaf leaf && leaf.isEmpty() && !leaf.computed()) {
            return b == null ? EMPTY : b;
        }
        if (b == null || b instanceof Leaf leaf && leaf.isEmpty() && !leaf.computed()) {
            return a;
        }
        if (entries(a).isPresent() != entries(b).isPresent()) {
            return merge(values(a), values(b));
        }
        if (a instanceof Composite left && b instanceof Composite right && left.type().equals(right.type())) {
            Map<String, Shape> components = new LinkedHashMap<>(left.components());
            right.components().forEach((name, shape) -> components.merge(name, shape, Shape::merge));
            return new Composite(left.type(), components);
        }
        if (!functions(a).isEmpty() && !functions(b).isEmpty()) {
            Set<Function> alternatives = new LinkedHashSet<>(functions(a));
            alternatives.addAll(functions(b));
            return alternatives.size() == 1 ? alternatives.iterator().next() : new Functions(List.copyOf(alternatives));
        }
        if (!functions(a).isEmpty()) {
            return a;
        }
        if (!functions(b).isEmpty()) {
            return b;
        }
        if (a instanceof Leaf left && b instanceof Leaf right) {
            return union(a, b, left.computed() || right.computed());
        }
        // Mixed structures (e.g. different types on two branches) collapse into a computed leaf.
        return union(a, b, true);
    }

    /**
     * Collapses shapes into one leaf holding all their fields and params.
     */
    static Leaf union(Shape a, Shape b, boolean computed) {
        Set<String> fields = new LinkedHashSet<>();
        Set<Integer> params = new LinkedHashSet<>();
        collect(a, fields, params);
        collect(b, fields, params);
        return new Leaf(fields, params, computed);
    }

    /**
     * The result of an operation on the given values: computed from all their fields and params.
     */
    static Leaf computed(Iterable<Shape> shapes) {
        Set<String> fields = new LinkedHashSet<>();
        Set<Integer> params = new LinkedHashSet<>();
        for (Shape shape : shapes) {
            collect(shape, fields, params);
        }
        return fields.isEmpty() && params.isEmpty() ? EMPTY : new Leaf(fields, params, true);
    }

    static void collect(Shape shape, Set<String> fields, Set<Integer> params) {
        if (shape instanceof Leaf leaf) {
            fields.addAll(leaf.fields());
            params.addAll(leaf.params());
        }
        else if (shape instanceof Composite composite) {
            composite.components().values().forEach(component -> collect(component, fields, params));
        }
    }

    /**
     * Every field the shape holds, at any depth.
     */
    static Set<String> fields(Shape shape) {
        Set<String> fields = new LinkedHashSet<>();
        collect(shape, fields, new LinkedHashSet<>());
        return fields;
    }
}
