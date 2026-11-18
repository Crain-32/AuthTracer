package dev.crain.authtracer.scan.flow;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.ClassFileMetadata;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JThisRef;
import sootup.core.types.ArrayType;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootMethod;

/**
 * The static type of a value in a method, with generic arguments where the bytecode's signatures say them:
 * {@code owners.findById(id).orElseThrow()} is an {@code Owner}, and {@code page.getContent()} on a
 * {@code Page<Owner>} a {@code List<Owner>}. A call's generic return type has the receiver's type arguments
 * substituted, found through the receiver class's generic supertypes up to the class declaring the method.
 */
@Supports({Feature.VIEW_FIELDS, Feature.WEBSOCKET_MESSAGES, Feature.RESPONSE_FIELDS})
public final class GenericTypes {

    private static final int MAX_DEPTH = 12;
    private static final GenericType OBJECT = new GenericType("java.lang.Object", List.of());
    /** The containers whose elements are what Jackson writes, and which of their type arguments that is. */
    private static final List<Map.Entry<String, Integer>> CONTAINERS = List.of(Map.entry("java.lang.Iterable", 0),
            Map.entry("java.util.Map", 1), Map.entry("java.util.stream.Stream", 0), Map.entry("java.util.Optional", 0));

    private final ScanContext context;

    public GenericTypes(ScanContext context) {
        this.context = context;
    }

    public Optional<GenericType> of(JavaSootMethod method, Value value) {
        return of(method, value, 0);
    }

    /**
     * The element type of a collection, array, {@code Optional} or stream type, e.g. {@code Pet} for
     * {@code List<Pet>}, {@code Page<Pet>} or {@code ArrayList<Pet>}, and a map's value type; else the type itself.
     */
    public GenericType element(GenericType type) {
        if (type.name().endsWith("[]")) {
            return new GenericType(type.name().substring(0, type.name().length() - 2), List.of());
        }
        if (type.arguments().isEmpty()) {
            return type;
        }
        for (Map.Entry<String, Integer> container : CONTAINERS) {
            Optional<GenericType> seen = as(type, container.getKey());
            if (seen.isPresent() && container.getValue() < seen.get().arguments().size()) {
                return seen.get().arguments().get(container.getValue());
            }
        }
        return type;
    }

    /**
     * The type seen as one of its supertypes, with its arguments carried there: {@code Page<Pet>} as
     * {@code java.lang.Iterable} is {@code Iterable<Pet>}.
     */
    public Optional<GenericType> as(GenericType type, String supertype) {
        return as(type, supertype, 0);
    }

    private Optional<GenericType> as(GenericType type, String supertype, int depth) {
        if (type.name().equals(supertype)) {
            return Optional.of(type);
        }
        if (depth > MAX_DEPTH) {
            return Optional.empty();
        }
        ClassFileMetadata.GenericDeclaration declaration = context.classFiles().declaration(type.name());
        Map<String, GenericType> own = new HashMap<>();
        for (int i = 0; i < declaration.typeParameters().size() && i < type.arguments().size(); i++) {
            own.put(declaration.typeParameters().get(i), type.arguments().get(i));
        }
        for (GenericType parent : declaration.supertypes()) {
            Optional<GenericType> found = as(substitute(parent, own), supertype, depth + 1);
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    private Optional<GenericType> of(JavaSootMethod method, Value value, int depth) {
        if (depth > MAX_DEPTH) {
            return Optional.empty();
        }
        return switch (value) {
            case Local local -> method.hasBody() ? Locals.definition(method.getBody(), local)
                    .flatMap(definition -> of(method, definition, depth + 1)) : Optional.empty();
            case JParameterRef parameter -> {
                List<GenericType> generic = context.classFiles().genericParameterTypes(method.getSignature());
                yield parameter.getIndex() < generic.size() ? Optional.of(generic.get(parameter.getIndex()))
                        : erased(parameter.getType());
            }
            case JThisRef self -> erased(self.getType());
            case JNewExpr created -> erased(created.getType());
            case JCastExpr cast -> erased(cast.getType());
            case JFieldRef field -> context.classFiles().genericFieldType(
                    field.getFieldSignature().getDeclClassType().getFullyQualifiedName(),
                    field.getFieldSignature().getName()).or(() -> erased(field.getFieldSignature().getType()));
            case StringConstant ignored -> Optional.of(new GenericType("java.lang.String", List.of()));
            case AbstractInvokeExpr invoke -> call(method, invoke, depth);
            default -> erased(value.getType());
        };
    }

    private Optional<GenericType> call(JavaSootMethod method, AbstractInvokeExpr invoke, int depth) {
        // javac names the receiver's static type; the method may be declared further up (Page#getContent is Slice's).
        Optional<String> declaring = declaring(invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName(),
                invoke, 0);
        Optional<GenericType> generic = declaring.flatMap(owner -> context.classFiles()
                .genericReturnTypeIn(owner, invoke.getMethodSignature()));
        if (generic.isEmpty()) {
            return erased(invoke.getMethodSignature().getType());
        }
        Map<String, GenericType> bindings = new HashMap<>();
        if (invoke instanceof AbstractInstanceInvokeExpr instance) {
            of(method, instance.getBase(), depth + 1).ifPresent(receiver -> bindings.putAll(bindings(receiver,
                    declaring.get(), 0)));
        }
        return Optional.of(substitute(generic.get(), bindings));
    }

    private Optional<String> declaring(String className, AbstractInvokeExpr invoke, int depth) {
        if (context.classFiles().declares(className, invoke.getMethodSignature())) {
            return Optional.of(className);
        }
        if (depth > MAX_DEPTH) {
            return Optional.empty();
        }
        for (GenericType supertype : context.classFiles().declaration(className).supertypes()) {
            Optional<String> found = declaring(supertype.name(), invoke, depth + 1);
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    /**
     * The declaring class's type parameters bound to the receiver's arguments, through its generic supertypes.
     */
    private Map<String, GenericType> bindings(GenericType receiver, String declaring, int depth) {
        if (depth > MAX_DEPTH) {
            return Map.of();
        }
        ClassFileMetadata.GenericDeclaration declaration = context.classFiles().declaration(receiver.name());
        Map<String, GenericType> own = new HashMap<>();
        List<String> parameters = declaration.typeParameters();
        for (int i = 0; i < parameters.size() && i < receiver.arguments().size(); i++) {
            own.put(parameters.get(i), receiver.arguments().get(i));
        }
        if (receiver.name().equals(declaring)) {
            return own;
        }
        for (GenericType supertype : declaration.supertypes()) {
            Map<String, GenericType> found = bindings(substitute(supertype, own), declaring, depth + 1);
            if (!found.isEmpty()) {
                return found;
            }
        }
        return Map.of();
    }

    private static GenericType substitute(GenericType type, Map<String, GenericType> bindings) {
        if (type.variable()) {
            return bindings.getOrDefault(type.name(), OBJECT);
        }
        return new GenericType(type.name(), type.arguments().stream().map(argument -> substitute(argument, bindings))
                .toList());
    }

    /**
     * Whether the class is a {@code Map}: its values are its elements.
     */
    public boolean isMap(String className) {
        return isA(className, "java.util.Map", 0);
    }

    private boolean isA(String className, String type, int depth) {
        if (className.equals(type)) {
            return true;
        }
        return depth <= MAX_DEPTH && context.classFiles().declaration(className).supertypes().stream()
                .anyMatch(supertype -> isA(supertype.name(), type, depth + 1));
    }

    private static Optional<GenericType> erased(Type type) {
        if (type instanceof ClassType cls) {
            return Optional.of(new GenericType(cls.getFullyQualifiedName(), List.of()));
        }
        if (type instanceof ArrayType array) {
            return Optional.of(new GenericType(array.toString(), List.of()));
        }
        return Optional.empty();
    }
}
