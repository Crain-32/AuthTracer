package dev.crain.authtracer.scan;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import sootup.core.jimple.common.constant.BooleanConstant;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.constant.EnumConstant;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.java.core.AnnotationUsage;

/**
 * Reads SootUp annotation values, which arrive as Jimple constants or lists of them.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class Annotations {

    private Annotations() {
    }

    public static String name(AnnotationUsage annotation) {
        return annotation.getAnnotation().getFullyQualifiedName();
    }

    public static Optional<String> string(AnnotationUsage annotation, String element) {
        List<String> values = strings(annotation, element);
        return values.isEmpty() ? Optional.empty() : Optional.of(values.getFirst());
    }

    /**
     * String, class, or enum values of an element; a single value is returned as a one-element list.
     */
    public static List<String> strings(AnnotationUsage annotation, String element) {
        Object value = annotation.getValues().get(element);
        if (value == null) {
            return List.of();
        }
        if (value instanceof Collection<?> values) {
            return values.stream().map(Annotations::asString).toList();
        }
        return List.of(asString(value));
    }

    public static Optional<Boolean> bool(AnnotationUsage annotation, String element) {
        Object value = annotation.getValues().get(element);
        // ASM reads a boolean element as a Boolean, which SootUp keeps as a BooleanConstant.
        return value instanceof BooleanConstant constant ? Optional.of(constant.getValue()) : Optional.empty();
    }

    public static Optional<Integer> integer(AnnotationUsage annotation, String element) {
        Object value = annotation.getValues().get(element);
        return value instanceof IntConstant constant ? Optional.of(constant.getValue()) : Optional.empty();
    }

    /**
     * Annotations nested in an element, e.g. the repeated annotations in a {@code @Repeatable} container's
     * {@code value}.
     */
    public static List<AnnotationUsage> nested(AnnotationUsage annotation, String element) {
        Object value = annotation.getValues().get(element);
        if (value instanceof Collection<?> values) {
            return values.stream().filter(AnnotationUsage.class::isInstance).map(AnnotationUsage.class::cast).toList();
        }
        return value instanceof AnnotationUsage single ? List.of(single) : List.of();
    }

    /**
     * Class values as fully qualified names ({@code java.lang.String}, not {@code Ljava/lang/String;}).
     */
    public static Optional<String> className(AnnotationUsage annotation, String element) {
        return string(annotation, element);
    }

    private static String asString(Object value) {
        if (value instanceof StringConstant constant) {
            return constant.getValue();
        }
        if (value instanceof ClassConstant constant) {
            String descriptor = constant.getValue();
            if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
                descriptor = descriptor.substring(1, descriptor.length() - 1);
            }
            return descriptor.replace('/', '.');
        }
        if (value instanceof EnumConstant constant) {
            return constant.getValue();
        }
        return String.valueOf(value);
    }
}
