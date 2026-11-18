package dev.crain.authtracer.scan.spring;

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.FieldSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * The text a value holds when the code takes it from the application's configuration, as Spring binds it: a
 * constant; a {@code @Value} parameter or field, or a field a constructor sets from one; and a getter of a
 * {@code @ConfigurationProperties} object, nested ones too ({@code clients.getPayments().getUrl()} reads
 * {@code clients.payments.url}), with relaxed binding, and the default its class gives when no file sets it (a field
 * initializer, a record component's {@code @DefaultValue}).
 */
@Supports({Feature.SERVICE_CALLS, Feature.MESSAGE_SENDS, Feature.GATEWAY_ROUTES, Feature.CALL_CREDENTIALS})
final class ConfiguredValues {

    static final String CONFIGURATION_PROPERTIES = "org.springframework.boot.context.properties.ConfigurationProperties";
    private static final String DEFAULT_VALUE = "org.springframework.boot.context.properties.bind.DefaultValue";
    private static final int DEPTH = 6;

    /**
     * @param value the text, {@code null} when the configuration doesn't say
     * @param expression where it comes from when that isn't the code itself, e.g. {@code ${orders.url}}
     */
    record Configured(String value, String expression) {

        static final Configured UNKNOWN = new Configured(null, null);

        boolean known() {
            return value != null || expression != null;
        }
    }

    /**
     * An object Spring binds to properties under the prefix.
     */
    private record Bound(String prefix, ClassType type) {
    }

    private final ScanContext context;

    ConfiguredValues(ScanContext context) {
        this.context = context;
    }

    Configured of(JavaSootMethod method, Value value) {
        return of(method, value, DEPTH);
    }

    private Configured of(JavaSootMethod method, Value value, int depth) {
        if (value instanceof StringConstant constant) {
            return new Configured(constant.getValue(), null);
        }
        if (!(value instanceof Local local) || depth == 0 || !method.hasBody()) {
            return Configured.UNKNOWN;
        }
        OptionalInt parameter = Locals.parameterIndex(method.getBody(), local);
        if (parameter.isPresent()) {
            return valueParameter(method, parameter.getAsInt());
        }
        Value definition = Locals.definition(method.getBody(), local).orElse(null);
        return switch (definition) {
            case JCastExpr cast -> of(method, cast.getOp(), depth - 1);
            case JFieldRef field -> field(field.getFieldSignature(), depth - 1);
            case AbstractInstanceInvokeExpr getter -> property(method, getter, depth - 1);
            case null, default -> Configured.UNKNOWN;
        };
    }

    /**
     * A field's {@code @Value}, else what its class's constructors set it to.
     */
    private Configured field(FieldSignature signature, int depth) {
        Optional<JavaSootClass> owner = context.findClass(signature.getDeclClassType());
        if (owner.isEmpty() || depth == 0) {
            return Configured.UNKNOWN;
        }
        Optional<Configured> annotated = owner.get().getField(signature.getName())
                .flatMap(declared -> context.findAnnotation(declared, SpringNames.VALUE))
                .flatMap(annotation -> Annotations.string(annotation, "value")).map(this::fromExpression);
        if (annotated.isPresent()) {
            return annotated.get();
        }
        for (JavaSootMethod constructor : owner.get().getMethods()) {
            if (!constructor.getName().equals("<init>") || !constructor.hasBody()) {
                continue;
            }
            for (Stmt stmt : constructor.getBody().getStmts()) {
                // A field initializer (private String hostname = "http://visits-service/") or a constructor
                // parameter's value.
                if (stmt instanceof AbstractDefinitionStmt assign && assign.getLeftOp() instanceof JFieldRef ref
                        && ref.getFieldSignature().getName().equals(signature.getName())) {
                    Configured set = of(constructor, assign.getRightOp(), depth - 1);
                    if (set.known()) {
                        return set;
                    }
                }
            }
        }
        return Configured.UNKNOWN;
    }

    /**
     * A getter called on an object bound to configuration properties.
     */
    private Configured property(JavaSootMethod method, AbstractInstanceInvokeExpr getter, int depth) {
        Optional<String> key = key(method, getter, depth);
        if (key.isEmpty()) {
            return Configured.UNKNOWN;
        }
        String value = context.properties().get(key.get())
                .orElseGet(() -> defaultOf(getter.getMethodSignature().getDeclClassType(),
                        name(getter).orElse("")).orElse(null));
        return new Configured(value, "${" + key.get() + "}");
    }

    private Optional<String> key(JavaSootMethod method, AbstractInstanceInvokeExpr getter, int depth) {
        Optional<String> property = name(getter);
        return property.flatMap(name -> bound(method, getter.getBase(), depth)
                .map(receiver -> receiver.prefix() + "." + kebab(name)));
    }

    /**
     * The object the value is, when Spring binds it: a parameter or field of a {@code @ConfigurationProperties}
     * type, or what a getter of one returns.
     */
    private Optional<Bound> bound(JavaSootMethod method, Value value, int depth) {
        if (!(value instanceof Local local) || depth == 0) {
            return Optional.empty();
        }
        Value definition = Locals.definition(method.getBody(), local).orElse(null);
        if (definition instanceof AbstractInstanceInvokeExpr getter) {
            return key(method, getter, depth - 1).map(key -> new Bound(key, null));
        }
        Type type = definition instanceof JFieldRef field ? field.getFieldSignature().getType()
                : definition instanceof JCastExpr cast ? cast.getType() : local.getType();
        return type instanceof ClassType classType ? prefix(classType).map(prefix -> new Bound(prefix, classType))
                : Optional.empty();
    }

    /**
     * The prefix a type is bound under: its own {@code @ConfigurationProperties}, else the one on the {@code @Bean}
     * method that returns it.
     */
    private Optional<String> prefix(ClassType type) {
        Optional<AnnotationUsage> annotation = context.findClass(type)
                .flatMap(cls -> context.findAnnotation(cls, CONFIGURATION_PROPERTIES))
                .or(() -> SpringBeans.beanMethods(context).stream().filter(bean -> bean.getReturnType().equals(type))
                        .flatMap(bean -> context.findAnnotation(bean, CONFIGURATION_PROPERTIES).stream()).findFirst());
        return annotation.flatMap(found -> Annotations.string(found, "prefix").filter(prefix -> !prefix.isEmpty())
                .or(() -> Annotations.string(found, "value"))).filter(prefix -> !prefix.isEmpty());
    }

    /**
     * The property a getter reads: a record's component, else a JavaBean property.
     */
    private Optional<String> name(AbstractInvokeExpr getter) {
        if (getter.getArgCount() != 0) {
            return Optional.empty();
        }
        String name = getter.getMethodSignature().getName();
        String owner = getter.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        return context.classFiles().isRecord(owner) ? Optional.of(name) : ClassFileMetadata.property(name);
    }

    /**
     * What the class binds when no file sets the property: its field's initializer, or a record component's
     * {@code @DefaultValue}.
     */
    private Optional<String> defaultOf(ClassType type, String property) {
        Optional<JavaSootClass> cls = context.findClass(type);
        if (cls.isEmpty()) {
            return Optional.empty();
        }
        if (context.classFiles().isRecord(type.getFullyQualifiedName())) {
            List<ClassFileMetadata.Member> components = context.classFiles()
                    .recordComponents(type.getFullyQualifiedName()).orElse(List.of());
            for (JavaSootMethod constructor : cls.get().getMethods()) {
                if (constructor.getName().equals("<init>") && constructor.getParameterCount() == components.size()) {
                    for (int i = 0; i < components.size(); i++) {
                        if (components.get(i).name().equals(property)) {
                            return context.classFiles().parameterAnnotationElement(constructor.getSignature(), i,
                                    DEFAULT_VALUE, "value");
                        }
                    }
                }
            }
            return Optional.empty();
        }
        Configured initialized = cls.get().getField(property).map(field -> field(field.getSignature(), DEPTH))
                .orElse(Configured.UNKNOWN);
        return Optional.ofNullable(initialized.value());
    }

    private Configured valueParameter(JavaSootMethod method, int parameter) {
        return context.classFiles().parameterAnnotationValue(method.getSignature(), parameter, SpringNames.VALUE)
                .map(this::fromExpression).orElse(Configured.UNKNOWN);
    }

    private Configured fromExpression(String expression) {
        return new Configured(context.properties().resolve(expression).orElse(null), expression);
    }

    /**
     * {@code baseUrl} → {@code base-url}, the form Spring Boot documents properties in.
     */
    static String kebab(String name) {
        StringBuilder result = new StringBuilder();
        for (char c : name.toCharArray()) {
            if (Character.isUpperCase(c)) {
                result.append('-').append(Character.toLowerCase(c));
            }
            else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
