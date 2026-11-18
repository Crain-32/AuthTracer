package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.expr.JSpecialInvokeExpr;
import sootup.core.jimple.common.expr.JStaticInvokeExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.FieldSignature;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0088: the proxy factory a {@code proxy(..)} call is made on, and what it applies. Spring Security's
 * {@code AuthorizationProxyFactory} bean applies every AuthorizationAdvisor bean (decision 0077). A factory the
 * application builds applies only the interceptors it is built with (7.1.1): {@code AuthorizationAdvisorProxyFactory
 * .withDefaults()} and {@code withReactiveDefaults()} the pre/post, filter and {@code @AuthorizeReturnObject} ones;
 * {@code new AuthorizationAdvisorProxyFactory(list)} those listed. Its interceptors are Spring's defaults: the
 * {@code ROLE_} prefix, no RoleHierarchy, no AuthorizationManagerFactory.
 */
@Supports({Feature.FIELD_CHECKS, Feature.METHOD_SECURITY})
final class ProxyFactories {

    static final String FACTORY = "org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory";
    private static final String INTERFACE = "org.springframework.security.authorization.AuthorizationProxyFactory";
    private static final String RETURN_OBJECT_INTERCEPTOR =
            "org.springframework.security.authorization.method.AuthorizeReturnObjectMethodInterceptor";
    private static final String CUSTOMIZER = "org.springframework.security.config.Customizer";
    private static final SortedSet<String> DEFAULTS = Collections.unmodifiableSortedSet(new TreeSet<>(List.of(
            SpringNames.PRE_AUTHORIZE, SpringNames.POST_AUTHORIZE, SpringNames.PRE_FILTER, SpringNames.POST_FILTER,
            SpringNames.AUTHORIZE_RETURN_OBJECT)));
    private static final int DEPTH = 3;

    /**
     * What a proxy factory applies to the objects it proxies.
     *
     * @param annotations the annotations whose interceptors a factory the application built has
     *        ({@code @RolesAllowed} for JSR-250's, {@code @AuthorizeReturnObject} among them); {@code null} for
     *        Spring Security's bean, which has every advisor
     * @param customized Spring Security's bean, whose advisors a customizer replaced with these
     */
    record Factory(SortedSet<String> annotations, boolean customized) {

        static final Factory SPRING = new Factory(null);

        Factory(SortedSet<String> annotations) {
            this(annotations, false);
        }

        boolean spring() {
            return annotations == null;
        }

        boolean applies(String annotation) {
            return spring() || annotations.contains(SpringNames.JSR_250.contains(annotation)
                    ? SpringNames.ROLES_ALLOWED : annotation);
        }

        /**
         * What either may apply: a value that may come from both is guarded only by what both apply.
         */
        Factory and(Factory other) {
            if (spring() || other.spring()) {
                return spring() ? other : this;
            }
            SortedSet<String> both = new TreeSet<>(annotations);
            both.retainAll(other.annotations);
            return new Factory(Collections.unmodifiableSortedSet(both), customized || other.customized);
        }

        /**
         * Which factory it is, for a finding: {@code ... which applies only @PreAuthorize} follows.
         */
        String madeBy() {
            return customized ? "Spring Security's proxy factory, which a customizer sets to apply"
                    : "a proxy factory the application builds, which applies";
        }

        /**
         * The interceptors it applies, in the order they run: {@code only @PreAuthorize, @Secured}.
         */
        String describe() {
            return annotations.isEmpty() ? "none of Spring's interceptors" : "only " + annotations.stream()
                    .sorted(Comparator.comparing(name -> MethodAdvisors.ORDERS.getOrDefault(name, Integer.MAX_VALUE)))
                    .map(name -> "@" + MethodNames.simpleName(name)).collect(Collectors.joining(", "));
        }
    }

    private final ScanContext context;
    private final GraphBuilder graph;
    private final Map<String, Factory> calls = new HashMap<>();
    private Factory built;
    private Factory spring;
    private List<JavaSootMethod> customizers;
    private List<Factory> factories;

    ProxyFactories(ScanContext context, GraphBuilder graph) {
        this.context = context;
        this.graph = graph;
    }

    /**
     * The factory the {@code proxy(..)} call is made on: one the method or its class builds, or Spring Security's
     * bean when it is injected; when it can't tell, what both Spring's bean and every factory the application builds
     * apply.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    Factory of(JavaSootMethod caller, AbstractInvokeExpr proxyCall) {
        String key = MethodNames.key(caller.getSignature()) + " " + proxyCall;
        Factory known = calls.get(key);
        if (known == null) {
            Optional<Factory> traced = proxyCall instanceof AbstractInstanceInvokeExpr instance
                    ? resolve(caller, instance.getBase(), DEPTH) : Optional.empty();
            known = traced.orElseGet(this::unknown);
            if (traced.isEmpty() && !known.spring()) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, MethodNames.key(caller.getSignature())
                        + " proxies objects with a proxy factory AuthTracer can't trace; as the application builds"
                        + " its own, they show the checks that every factory it may be applies, " + known.describe(),
                        MethodNames.codeRef(caller.getSignature())));
            }
            calls.put(key, known);
        }
        return known;
    }

    private Optional<Factory> resolve(JavaSootMethod method, Value value, int depth) {
        if (depth == 0 || !method.hasBody()) {
            return Optional.empty();
        }
        if (value instanceof Local local) {
            List<Value> definitions = Locals.definitions(method.getBody(), local);
            Factory all = null;
            for (Value definition : definitions) {
                Optional<Factory> one = definition instanceof JNewExpr ? created(method, local)
                        : resolve(method, definition, depth);
                if (one.isEmpty()) {
                    return Optional.empty();
                }
                all = all == null ? one.get() : all.and(one.get());
            }
            return Optional.ofNullable(all);
        }
        if (value instanceof JCastExpr cast) {
            return resolve(method, cast.getOp(), depth);
        }
        if (value instanceof JParameterRef) {
            // Injected: Spring Security's bean, and the application's own factory beans if it declares any.
            return injectable(method) ? Optional.of(beans()) : Optional.empty();
        }
        if (value instanceof JFieldRef field) {
            return assigned(field.getFieldSignature(), depth - 1);
        }
        if (value instanceof JStaticInvokeExpr call && call.getMethodSignature().getDeclClassType()
                .getFullyQualifiedName().equals(FACTORY)) {
            String name = call.getMethodSignature().getName();
            return name.equals("withDefaults") || name.equals("withReactiveDefaults")
                    ? Optional.of(new Factory(DEFAULTS)) : Optional.empty();
        }
        if (value instanceof AbstractInvokeExpr call && context.isApplication(call.getMethodSignature()
                .getDeclClassType())) {
            return context.findMethod(call.getMethodSignature()).flatMap(called -> returned(called, depth - 1));
        }
        return Optional.empty();
    }

    /**
     * What every value the method returns is.
     */
    private Optional<Factory> returned(JavaSootMethod method, int depth) {
        if (!method.hasBody()) {
            return Optional.empty();
        }
        Factory all = null;
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt result) {
                Optional<Factory> one = resolve(method, result.getOp(), depth);
                if (one.isEmpty()) {
                    return Optional.empty();
                }
                all = all == null ? one.get() : all.and(one.get());
            }
        }
        return Optional.ofNullable(all);
    }

    /**
     * What every assignment to the field, in its class, stores.
     */
    private Optional<Factory> assigned(FieldSignature field, int depth) {
        Optional<JavaSootClass> owner = context.findClass(field.getDeclClassType())
                .filter(cls -> context.isApplication(cls.getType()));
        if (owner.isEmpty()) {
            return Optional.empty();
        }
        Factory all = null;
        for (JavaSootMethod method : owner.get().getMethods()) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof JFieldRef ref
                        && ref.getFieldSignature().equals(field)) {
                    Optional<Factory> one = resolve(method, definition.getRightOp(), depth);
                    if (one.isEmpty()) {
                        return Optional.empty();
                    }
                    all = all == null ? one.get() : all.and(one.get());
                }
            }
        }
        return Optional.ofNullable(all);
    }

    /**
     * {@code new AuthorizationAdvisorProxyFactory(list)}: the interceptors listed that are Spring's, built with its
     * defaults; any other is an OPAQUE_CONFIG finding and isn't counted.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private Optional<Factory> created(JavaSootMethod method, Local local) {
        if (!Locals.created(method.getBody(), local).map(type -> type.getFullyQualifiedName().equals(FACTORY))
                .orElse(false)) {
            return Optional.empty();
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            if (Locals.invoke(stmt).orElse(null) instanceof JSpecialInvokeExpr init && init.getBase().equals(local)
                    && init.getMethodSignature().getName().equals("<init>") && init.getArgCount() == 1) {
                SortedSet<String> annotations = new TreeSet<>();
                List<Value> unread = new ArrayList<>();
                for (Value element : listed(method, init.getArg(0))) {
                    interceptor(element).ifPresentOrElse(annotations::add, () -> unread.add(element));
                }
                if (!unread.isEmpty()) {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, MethodNames.key(method.getSignature())
                            + " builds an AuthorizationAdvisorProxyFactory with advisors AuthTracer doesn't read;"
                            + " the objects it proxies show the checks of the Spring interceptors it lists, "
                            + new Factory(annotations).describe(),
                            MethodNames.codeRef(method.getSignature(), stmt)));
                }
                return Optional.of(new Factory(Collections.unmodifiableSortedSet(annotations)));
            }
        }
        return Optional.empty();
    }

    /**
     * The elements of {@code List.of(a, b)}, {@code List.of(array)} or {@code Arrays.asList(array)}, each followed to
     * its definition; a list the method fills with {@code add(..)} too.
     */
    private static List<Value> listed(JavaSootMethod method, Value list) {
        List<Value> elements = new ArrayList<>();
        if (!(list instanceof Local local)) {
            return elements;
        }
        if (Locals.definition(method.getBody(), local).orElse(null) instanceof AbstractInvokeExpr call) {
            for (Value arg : call.getArgs()) {
                List<Value> array = arg instanceof Local values ? Locals.elements(method.getBody(), values) : List.of();
                if (array.isEmpty()) {
                    elements.add(defined(method, arg));
                }
                elements.addAll(array);
            }
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            if (Locals.invoke(stmt).orElse(null) instanceof AbstractInstanceInvokeExpr add
                    && add.getBase().equals(local) && add.getMethodSignature().getName().equals("add")
                    && add.getArgCount() == 1) {
                elements.add(defined(method, add.getArg(0)));
            }
        }
        return elements;
    }

    private static Value defined(JavaSootMethod method, Value value) {
        return value instanceof Local local ? Locals.definition(method.getBody(), local).orElse(value) : value;
    }

    /**
     * A parameter Spring fills with a bean: a constructor's, an {@code @Bean} method's or an {@code @Autowired}
     * method's.
     */
    private boolean injectable(JavaSootMethod method) {
        return method.getName().equals("<init>") || context.hasAnnotation(method, SpringNames.BEAN)
                || context.hasAnnotation(method, "org.springframework.beans.factory.annotation.Autowired");
    }

    /**
     * FIELD-06: Spring Security's {@code AuthorizationProxyFactory} bean as the application's customizers leave it. A
     * {@code Customizer<AuthorizationAdvisorProxyFactory>} that calls {@code setAdvisors(..)} replaces every advisor
     * the bean has (the annotations' interceptors, {@code @AuthorizeReturnObject}'s and every AuthorizationAdvisor bean:
     * 7.1.1's {@code AuthorizationProxyConfiguration} applies the customizers after handing it the beans) with those it
     * lists; Spring's interceptors {@code addAdvisor(..)} adds count too. Others are OPAQUE_CONFIG findings
     * (MethodSecurity).
     */
    Factory spring() {
        if (spring == null) {
            boolean replaced = false;
            SortedSet<String> annotations = new TreeSet<>();
            for (JavaSootMethod customizer : customizers()) {
                for (Stmt stmt : customizer.getBody().getStmts()) {
                    if (Locals.invoke(stmt).orElse(null) instanceof AbstractInstanceInvokeExpr call
                            && call.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals(FACTORY)
                            && Locals.definition(customizer.getBody(), call.getBase()).orElse(null)
                                    instanceof JParameterRef
                            && Set.of("setAdvisors", "addAdvisor").contains(call.getMethodSignature().getName())) {
                        replaced |= call.getMethodSignature().getName().equals("setAdvisors");
                        for (Value arg : call.getArgs()) {
                            List<Value> advisors = arg instanceof Local local
                                    && !Locals.elements(customizer.getBody(), local).isEmpty()
                                            ? Locals.elements(customizer.getBody(), local) : listed(customizer, arg);
                            (advisors.isEmpty() ? List.of(defined(customizer, arg)) : advisors).forEach(advisor ->
                                    interceptor(advisor).ifPresent(annotations::add));
                        }
                    }
                }
            }
            spring = replaced ? new Factory(Collections.unmodifiableSortedSet(annotations), true) : Factory.SPRING;
        }
        return spring;
    }

    /**
     * The annotation one of Spring's interceptors, built with its defaults, reads.
     */
    private static Optional<String> interceptor(Value advisor) {
        return advisor instanceof JNewExpr created && created.getType().getFullyQualifiedName()
                .equals(RETURN_OBJECT_INTERCEPTOR) ? Optional.of(SpringNames.AUTHORIZE_RETURN_OBJECT)
                        : MethodAdvisors.defaultInterceptor(advisor);
    }

    /**
     * Whether the method customizes Spring Security's factory bean.
     */
    boolean customizes(JavaSootMethod method) {
        return customizers().contains(method);
    }

    /**
     * What customizes Spring Security's factory bean: the lambda a {@code @Bean} method returning a
     * {@code Customizer} makes, or a {@code Customizer}'s {@code customize(AuthorizationAdvisorProxyFactory)}.
     */
    private List<JavaSootMethod> customizers() {
        if (customizers != null) {
            return customizers;
        }
        customizers = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            Set<String> beanMethods = new HashSet<>();
            cls.getMethods().stream().filter(method -> context.hasAnnotation(method, SpringNames.BEAN)
                    && method.getReturnType().toString().equals(CUSTOMIZER)).forEach(method ->
                            beanMethods.add(method.getName()));
            for (JavaSootMethod method : cls.getMethods()) {
                boolean takesFactory = method.hasBody() && method.getParameterTypes().stream()
                        .anyMatch(type -> type.toString().equals(FACTORY));
                String name = method.getName();
                boolean lambda = name.startsWith("lambda$") && beanMethods.contains(name.split("\\$")[1]);
                boolean customize = name.equals("customize") && context.interfacesOf(cls.getType()).stream()
                        .anyMatch(type -> type.getFullyQualifiedName().equals(CUSTOMIZER));
                if (takesFactory && (lambda || customize)) {
                    customizers.add(method);
                }
            }
        }
        return customizers;
    }

    /**
     * What an injected factory is: Spring Security's bean, or one the application declares as a bean.
     */
    private Factory beans() {
        Factory all = spring();
        for (JavaSootMethod bean : SpringBeans.beanMethods(context, FACTORY, INTERFACE)) {
            all = all.and(returned(bean, DEPTH).orElse(Factory.SPRING));
        }
        return all;
    }

    /**
     * A factory AuthTracer can't trace: what Spring Security's bean and every factory the application builds apply.
     */
    private Factory unknown() {
        if (built == null) {
            built = spring();
            for (Factory factory : built()) {
                built = built.and(factory);
            }
        }
        return built;
    }

    /**
     * Decision 0088 (amended): whether a factory the application builds applies the annotation, so that its checks
     * run on the objects that factory proxies whether or not method security is enabled.
     */
    boolean builds(String annotation) {
        return built().stream().anyMatch(factory -> factory.applies(annotation));
    }

    /**
     * The factories the application builds: {@code withDefaults()}, {@code withReactiveDefaults()}, or
     * {@code new AuthorizationAdvisorProxyFactory(list)}.
     */
    private List<Factory> built() {
        if (factories == null) {
            factories = new ArrayList<>();
            for (JavaSootClass cls : context.applicationClasses()) {
                for (JavaSootMethod method : cls.getMethods()) {
                    if (!method.hasBody()) {
                        continue;
                    }
                    for (Stmt stmt : method.getBody().getStmts()) {
                        if (stmt instanceof AbstractDefinitionStmt definition
                                && definition.getLeftOp() instanceof Local local
                                && (definition.getRightOp() instanceof JNewExpr
                                        || definition.getRightOp() instanceof JStaticInvokeExpr)) {
                            (definition.getRightOp() instanceof JNewExpr ? created(method, local)
                                    : resolve(method, definition.getRightOp(), 1)).ifPresent(factories::add);
                        }
                    }
                }
            }
        }
        return factories;
    }
}
