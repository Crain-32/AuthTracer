package dev.crain.authtracer.scan.spring;

import java.beans.Introspector;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Which application classes Spring manages as beans, so their method-security annotations run through a proxy.
 */
@Supports({Feature.METHOD_SECURITY, Feature.CALL_PATHS, Feature.APPLICATION_GRAPH})
final class SpringBeans {

    private static final String SPRING_DATA_REPOSITORY = "org.springframework.data.repository.Repository";

    private final ScanContext context;
    private final Set<String> beanClasses = new HashSet<>();
    private final Set<String> proxiedTypes = new HashSet<>();

    /**
     * @param xmlBeans the classes the application's XML defines beans of (decision 0036)
     */
    SpringBeans(ScanContext context, Set<String> xmlBeans) {
        this.context = context;
        beanClasses.addAll(xmlBeans);
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!cls.isAnnotation() && context.hasAnnotation(cls, SpringNames.COMPONENT)) {
                beanClasses.add(cls.getName());
            }
            // Spring Data creates a bean for every repository interface it finds.
            if (cls.isInterface() && context.interfacesOf(cls.getType()).stream()
                    .anyMatch(type -> type.getFullyQualifiedName().equals(SPRING_DATA_REPOSITORY))) {
                beanClasses.add(cls.getName());
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (context.hasAnnotation(method, SpringNames.BEAN)
                        && method.getReturnType() instanceof ClassType returned) {
                    Optional<List<ClassType>> created = created(method);
                    if (created.isPresent()) {
                        // @Bean Notifier notifier() { return new EmailNotifier(); }: the bean is an EmailNotifier.
                        created.get().forEach(type -> beanClasses.add(type.getFullyQualifiedName()));
                    }
                    else {
                        beanClasses.add(returned.getFullyQualifiedName());
                        context.subtypesOf(returned).forEach(subtype -> beanClasses.add(
                                subtype.getFullyQualifiedName()));
                    }
                }
            }
        }
    }

    /**
     * The classes a bean method's body creates and returns, when every return is an object it creates.
     */
    private static Optional<List<ClassType>> created(JavaSootMethod method) {
        if (!method.hasBody()) {
            return Optional.empty();
        }
        List<ClassType> types = new ArrayList<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned) {
                Optional<ClassType> type = returned.getOp() instanceof Local local
                        ? Locals.created(method.getBody(), local) : Optional.empty();
                if (type.isEmpty()) {
                    return Optional.empty();
                }
                types.add(type.get());
            }
        }
        return types.isEmpty() ? Optional.empty() : Optional.of(types);
    }

    boolean isBean(ClassType type) {
        return beanClasses.contains(type.getFullyQualifiedName());
    }

    /**
     * Whether calls declared on the type go through a bean's proxy: the type is a bean's, or one of its supertypes
     * (an interface it implements, a class it extends), whose annotated methods the bean inherits.
     */
    boolean isProxied(ClassType type) {
        if (proxiedTypes.isEmpty()) {
            for (String bean : beanClasses) {
                ClassType beanType = context.type(bean);
                proxiedTypes.add(bean);
                context.superClassesOf(beanType).forEach(supertype -> proxiedTypes.add(
                        supertype.getFullyQualifiedName()));
                context.interfacesOf(beanType).forEach(supertype -> proxiedTypes.add(
                        supertype.getFullyQualifiedName()));
            }
        }
        return proxiedTypes.contains(type.getFullyQualifiedName());
    }

    boolean isController(JavaSootClass cls) {
        return isBean(cls.getType()) && context.hasAnnotation(cls, SpringNames.CONTROLLER);
    }

    /**
     * The application's {@code @Bean} methods.
     */
    static List<JavaSootMethod> beanMethods(ScanContext context) {
        return context.methodsAnnotated(SpringNames.BEAN);
    }

    /**
     * The application's {@code @Bean} methods whose declared return type is one of the types.
     */
    static List<JavaSootMethod> beanMethods(ScanContext context, String... returnTypes) {
        return beanMethods(context, Set.of(returnTypes));
    }

    /**
     * The application's {@code @Bean} methods whose declared return type is one of the types.
     */
    static List<JavaSootMethod> beanMethods(ScanContext context, Set<String> returnTypes) {
        return beanMethods(context).stream().filter(method -> method.getReturnType() instanceof ClassType returned
                && returnTypes.contains(returned.getFullyQualifiedName())).toList();
    }

    /**
     * The application's {@code @Bean} methods whose declared return type is one of the types or a subtype of one: a
     * {@code DefaultSecurityFilterChain} bean (as a Kotlin {@code = http.build()} infers it) is a
     * {@code SecurityFilterChain}.
     */
    static List<JavaSootMethod> beanMethodsOf(ScanContext context, Set<String> types) {
        return beanMethods(context).stream().filter(method -> method.getReturnType() instanceof ClassType returned
                && assignable(context, returned, types)).toList();
    }

    /**
     * Whether the type is one of the types, or extends or implements one.
     */
    static boolean assignable(ScanContext context, ClassType type, Set<String> types) {
        return types.contains(type.getFullyQualifiedName())
                || context.superClassesOf(type).stream().anyMatch(supertype -> types.contains(
                        supertype.getFullyQualifiedName()))
                || context.interfacesOf(type).stream().anyMatch(supertype -> types.contains(
                        supertype.getFullyQualifiedName()));
    }

    /**
     * A component's bean name, as Spring's {@code AnnotationBeanNameGenerator} gives it: the {@code value} of its
     * stereotype ({@code @Component("audit")}, {@code @Service("archive")}), else its simple name decapitalized.
     */
    static String beanName(ScanContext context, JavaSootClass cls) {
        for (AnnotationUsage annotation : cls.getAnnotations()) {
            String name = Annotations.name(annotation);
            boolean stereotype = name.equals(SpringNames.COMPONENT) || context.metaAnnotations(name).stream()
                    .anyMatch(meta -> Annotations.name(meta).equals(SpringNames.COMPONENT));
            Optional<String> value = stereotype ? Annotations.string(annotation, "value").filter(found -> !found
                    .isEmpty()) : Optional.empty();
            if (value.isPresent()) {
                return value.get();
            }
        }
        String className = cls.getType().getClassName();
        return Introspector.decapitalize(className.substring(className.lastIndexOf('$') + 1));
    }
}
