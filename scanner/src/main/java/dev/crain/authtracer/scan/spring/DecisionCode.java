package dev.crain.authtracer.scan.spring;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.MethodModifier;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0064 (EXPR-03, AUTHZ-01, AUTHZ-02, RX-02, OAUTH-04): the application code that decides a check, resolved to
 * its class and method, so the check says who decides it ({@link Requirement#decidedBy()}): a SpEL bean's method
 * ({@code @authz.canRead(#id)}), a custom {@code AuthorizationManager} or {@code ReactiveAuthorizationManager} class
 * (created with {@code new}, a bean handed in by type or name), or a lambda. A bean Spring Security provides the
 * methods of ({@code DefaultOAuth2AuthorizationManagerFactory}'s {@code hasScope}, an
 * {@code AuthorizationManagerFactory}'s {@code hasRole}) is read as what it builds.
 */
@Supports(Feature.CUSTOM_DECISIONS)
final class DecisionCode {

    static final String AUTHORIZATION_MANAGER = "org.springframework.security.authorization.AuthorizationManager";
    static final String REACTIVE_MANAGER = "org.springframework.security.authorization.ReactiveAuthorizationManager";
    private static final Set<String> MANAGERS = Set.of(AUTHORIZATION_MANAGER, REACTIVE_MANAGER);
    private static final String OAUTH2_FACTORY =
            "org.springframework.security.oauth2.core.authorization.OAuth2AuthorizationManagerFactory";
    private static final String DEFAULT_OAUTH2_FACTORY =
            "org.springframework.security.oauth2.core.authorization.DefaultOAuth2AuthorizationManagerFactory";
    private static final String MANAGER_FACTORY = "org.springframework.security.authorization.AuthorizationManagerFactory";
    private static final String DEFAULT_MANAGER_FACTORY =
            "org.springframework.security.authorization.DefaultAuthorizationManagerFactory";

    /**
     * One per scan. The scan holds its own strongly ({@link SpringSecurityModule}); the cache only weakly, so neither
     * keeps a finished scan's view alive.
     */
    private static final Map<ScanContext, WeakReference<DecisionCode>> CACHE =
            Collections.synchronizedMap(new WeakHashMap<>());

    /**
     * A bean the application defines: its class, and the {@code @Bean} method that makes it, if one does.
     */
    record Bean(ClassType type, JavaSootMethod factory) {
    }

    private final ScanContext context;
    private final Map<String, List<Bean>> byName = new LinkedHashMap<>();
    private final Set<String> missing = Collections.synchronizedSet(new LinkedHashSet<>());
    /**
     * EXPR-05: the methods of a handler's root the annotations never use, which expressions call.
     */
    private final Set<String> failing = Collections.synchronizedSet(new LinkedHashSet<>());
    private final Map<CodeRef, DecisionBodies.Reading> readings = new ConcurrentHashMap<>();
    private final Map<CodeRef, JavaSootMethod> methods = new ConcurrentHashMap<>();

    private DecisionCode(ScanContext context) {
        this.context = context;
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!cls.isAnnotation() && !cls.isInterface() && context.hasAnnotation(cls, SpringNames.COMPONENT)) {
                byName.computeIfAbsent(SpringBeans.beanName(context, cls), name -> new ArrayList<>())
                        .add(new Bean(cls.getType(), null));
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (method.hasBody() && context.hasAnnotation(method, SpringNames.BEAN)
                        && method.getReturnType() instanceof ClassType returned) {
                    ClassType type = created(method).orElse(returned);
                    for (String name : beanNames(method)) {
                        byName.computeIfAbsent(name, found -> new ArrayList<>()).add(new Bean(type, method));
                    }
                }
            }
        }
    }

    static DecisionCode of(ScanContext context) {
        synchronized (CACHE) {
            WeakReference<DecisionCode> cached = CACHE.get(context);
            DecisionCode decisionCode = cached == null ? null : cached.get();
            if (decisionCode == null) {
                decisionCode = new DecisionCode(context);
                CACHE.put(context, new WeakReference<>(decisionCode));
            }
            return decisionCode;
        }
    }

    /**
     * The findings about the code that decides the graph's checks: each decision method AuthTracer can't reduce is one
     * OPAQUE_CONFIG finding, and so is each SpEL bean name no bean of the application has (if there is none, the
     * expression fails and every caller is denied, but it may be a library's).
     */
    @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_ALWAYS_GRANTED, Feature.FINDING_OPAQUE_CONFIG,
            Feature.AUTHORITY_SOURCE})
    void report(GraphBuilder graph) {
        List<AuthorizationLocation> locations = graph.nodes().stream()
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> !graph.splits().containsKey(location.id())).toList();
        Map<Requirement.Kind, Map<CodeRef, List<AuthorizationLocation>>> decided = new LinkedHashMap<>();
        for (AuthorizationLocation location : locations) {
            Map<CodeRef, Requirement.Kind> codes = new LinkedHashMap<>();
            decisions(location.requirement(), codes);
            codes.forEach((code, kind) -> decided.computeIfAbsent(kind, key -> new LinkedHashMap<>())
                    .computeIfAbsent(code, key -> new ArrayList<>()).add(location));
            // SRC-14: code that reads a store or calls out decides on what is current, not on the token's snapshot.
            if (codes.keySet().stream().anyMatch(this::live)) {
                graph.replace(location.withFreshness(AuthoritySource.Freshness.LIVE));
            }
        }
        decided.getOrDefault(Requirement.Kind.EXPRESSION, Map.of()).forEach((code, checks) -> graph.finding(
                new Finding(Finding.Kind.OPAQUE_CONFIG, code.key() + " decides " + checks(checks) + " in a way"
                        + " AuthTracer can't reduce" + details(code) + ": " + (checks.size() == 1 ? "it is" : "they are")
                        + " shown as custom, decided by it", code)));
        // Decision 0065: permit-all in disguise, and its opposite.
        decided.getOrDefault(Requirement.Kind.PERMIT_ALL, Map.of()).forEach((code, checks) -> graph.finding(
                new Finding(Finding.Kind.ALWAYS_GRANTED, code.key() + " grants every caller, so " + checks(checks)
                        + " lets anyone through although it reads as if it asks for something", code)));
        decided.getOrDefault(Requirement.Kind.DENY_ALL, Map.of()).forEach((code, checks) -> graph.finding(
                new Finding(Finding.Kind.ALWAYS_DENIED, code.key() + " denies every caller, so what "
                        + checks(checks) + " guards can't be reached", code)));
        for (String method : List.copyOf(failing)) {
            locations.stream().filter(location -> mentions(location.requirement(), method + "("))
                    .forEach(location -> graph.finding(new Finding(Finding.Kind.ALWAYS_DENIED, location.mechanism()
                            + " on " + location.target().key() + " calls " + method + "(..), which only the expression"
                            + " handler's own root has, and pre/post annotations never use that root: the expression"
                            + " fails, so every caller is denied", location.target())));
        }
        for (String bean : List.copyOf(missing)) {
            locations.stream().filter(location -> mentions(location.requirement(), "@" + bean + "."))
                    .findFirst().ifPresent(location -> graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG,
                            location.mechanism() + " on " + location.target().key() + " calls the bean @" + bean
                                    + ", which AuthTracer finds no bean for: if there is none, the expression fails"
                                    + " and every caller is denied", location.target())));
        }
    }

    /**
     * The code that decides parts of the requirement, with what each part came to.
     */
    private static void decisions(Requirement requirement, Map<CodeRef, Requirement.Kind> found) {
        if (requirement.decidedBy() != null) {
            found.putIfAbsent(requirement.decidedBy(), requirement.kind());
            return;
        }
        requirement.operands().forEach(operand -> decisions(operand, found));
    }

    /**
     * What the body shows besides the decision: the stores it reads, the services it calls, a thrown denial.
     */
    private String details(CodeRef code) {
        DecisionBodies.Reading reading = readings.get(code);
        if (reading == null) {
            return "";
        }
        List<String> details = new ArrayList<>();
        if (!reading.reads().isEmpty()) {
            details.add("it reads " + String.join(", ", reading.reads()) + ", so what it decides is Live");
        }
        if (!reading.calls().isEmpty()) {
            details.add("it calls another service (" + String.join(", ", reading.calls()) + ")");
        }
        if (reading.throwsDenial()) {
            details.add("it denies by throwing");
        }
        return details.isEmpty() ? "" : " (" + String.join("; ", details) + ")";
    }

    private static boolean mentions(Requirement requirement, String text) {
        return requirement.expression() != null && requirement.expression().contains(text)
                || requirement.operands().stream().anyMatch(operand -> mentions(operand, text));
    }

    private static String checks(List<AuthorizationLocation> decided) {
        AuthorizationLocation first = decided.getFirst();
        String one = first.mechanism() + " on " + (first.routePattern() != null ? first.routePattern()
                : first.target().key());
        return decided.size() == 1 ? one : decided.size() + " checks (" + one + ", ...)";
    }

    /**
     * {@code @bean.method(args)} in a SpEL expression.
     *
     * @param literals the arguments' values where they are string literals, {@code null} where they aren't
     * @param expression the expression the call is, kept as the requirement's source
     */
    Requirement beanCall(String beanName, String methodName, List<String> literals, String expression) {
        List<Bean> beans = byName.getOrDefault(beanName, List.of());
        if (beans.size() != 1) {
            if (beans.isEmpty()) {
                missing.add(beanName);
            }
            return Requirement.expression(expression);
        }
        Bean bean = beans.getFirst();
        Optional<Requirement> provided = providedMethods(bean, methodName, literals, expression);
        if (provided.isPresent()) {
            return provided.get();
        }
        return method(bean.type(), methodName, literals.size())
                .map(method -> decided(method, expression))
                .orElseGet(() -> Requirement.custom(expression, bean.factory() != null
                        ? MethodNames.codeRef(bean.factory().getSignature())
                        : CodeRef.ofClass(bean.type().getFullyQualifiedName())));
    }

    /**
     * Decision 0091 (EXPR-05): {@code method(args)} in a SpEL expression that the handler's own root answers: what
     * its method decides; when the annotations never use that root, the call fails and nobody passes.
     */
    Optional<Requirement> rootCall(ClassType root, String methodName, List<String> literals, String expression,
            boolean ignored) {
        return method(root, methodName, literals.size()).map(method -> {
            if (ignored) {
                failing.add(methodName);
                return Requirement.denyAll().withSource(expression);
            }
            return decided(method, expression);
        });
    }

    /**
     * A manager the code creates with {@code new}: what its {@code authorize} method decides, when it is the
     * application's.
     */
    Optional<Requirement> created(ClassType type, String expression) {
        if (!context.isApplication(type) || !isManager(type)) {
            return Optional.empty();
        }
        return Optional.of(authorizeMethod(type).map(method -> decided(method, expression))
                .orElseGet(() -> Requirement.custom(expression, CodeRef.ofClass(type.getFullyQualifiedName()))));
    }

    /**
     * A lambda or method reference given as a manager: what its body decides.
     */
    Requirement lambda(MethodSignature target, String expression) {
        return context.findMethod(target).filter(JavaSootMethod::hasBody).map(method -> decided(method, expression))
                .orElseGet(() -> Requirement.custom(expression, MethodNames.codeRef(target)));
    }

    /**
     * A manager handed in (a bean method's parameter, a field): the application class it is declared as, else the
     * one bean of a manager type, or the one named like it.
     */
    Optional<Requirement> injected(Type declared, String name, String expression) {
        if (!(declared instanceof ClassType type)) {
            return Optional.empty();
        }
        if (context.isApplication(type)) {
            return created(type, expression);
        }
        if (!SpringBeans.assignable(context, type, MANAGERS)) {
            return Optional.empty();
        }
        List<Bean> candidates = byName.values().stream().flatMap(List::stream)
                .filter(bean -> bean.factory() == null ? isManager(bean.type()) : SpringBeans.assignable(context,
                        (ClassType) bean.factory().getReturnType(), Set.of(type.getFullyQualifiedName()))).toList();
        List<Bean> named = byName.getOrDefault(name, List.of()).stream().filter(candidates::contains).toList();
        List<Bean> chosen = candidates.size() == 1 ? candidates : named;
        return chosen.size() == 1 ? fromBean(chosen.getFirst(), expression) : Optional.empty();
    }

    /**
     * Decision 0097: the one bean of that name the application's code defines (a component or a {@code @Bean}
     * method), if there is one.
     */
    Optional<Bean> named(String beanName) {
        List<Bean> beans = byName.getOrDefault(beanName, List.of());
        return beans.size() == 1 ? Optional.of(beans.getFirst()) : Optional.empty();
    }

    /**
     * Decision 0097: what the manager bean of that name decides, when it is the application's code: the class it
     * is, or the lambda its {@code @Bean} method returns.
     */
    Optional<Requirement> namedManager(String beanName, String expression) {
        return named(beanName).flatMap(bean -> fromBean(bean, expression));
    }

    /**
     * The class of the bean a value declared as {@code declared} is: the class itself when it is the application's,
     * else the one bean of the type, or the one named like it.
     */
    Optional<ClassType> beanClass(ClassType declared, String name, String type) {
        if (context.isApplication(declared) && !context.findClass(declared).map(JavaSootClass::isInterface)
                .orElse(false)) {
            return Optional.of(declared);
        }
        List<Bean> candidates = byName.values().stream().flatMap(List::stream)
                .filter(bean -> SpringBeans.assignable(context, bean.type(), Set.of(type))
                        && SpringBeans.assignable(context, bean.type(), Set.of(declared.getFullyQualifiedName())))
                .toList();
        List<Bean> named = byName.getOrDefault(name, List.of()).stream().filter(candidates::contains).toList();
        List<Bean> chosen = candidates.size() == 1 ? candidates : named;
        return chosen.size() == 1 ? Optional.of(chosen.getFirst().type()) : Optional.empty();
    }

    /**
     * EXPR-06: {@code hasPermission(..)} with this many arguments, as the evaluator class's method decides it.
     */
    Requirement permission(ClassType evaluator, int arguments, String expression) {
        return method(evaluator, "hasPermission", arguments + 1).map(method -> decided(method, expression))
                .orElseGet(() -> Requirement.custom(expression, CodeRef.ofClass(evaluator.getFullyQualifiedName())));
    }

    /**
     * What a manager bean is: the class it creates, or the lambda its {@code @Bean} method returns.
     */
    private Optional<Requirement> fromBean(Bean bean, String expression) {
        if (bean.factory() == null || context.isApplication(bean.type())) {
            return created(bean.type(), expression);
        }
        for (Stmt stmt : bean.factory().getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned && returned.getOp() instanceof Local local) {
                Optional<MethodSignature> target = Locals.definition(bean.factory().getBody(), local)
                        .flatMap(DecisionCode::lambdaTarget);
                if (target.isPresent() && context.isApplication(target.get().getDeclClassType())) {
                    return Optional.of(lambda(target.get(), expression));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Whether a lambda's method is shaped like a manager's {@code authorize(Supplier<Authentication>, T)}, or the
     * reactive {@code authorize(Mono<Authentication>, T)}, rather than a {@code RequestMatcher} or a customizer: its
     * last two parameters, after what it captures.
     */
    static boolean isManagerLambda(MethodSignature target) {
        List<Type> parameters = target.getParameterTypes();
        return parameters.size() >= 2 && Set.of("java.util.function.Supplier", "reactor.core.publisher.Mono")
                .contains(parameters.get(parameters.size() - 2).toString());
    }

    /**
     * The method a lambda or method reference ({@code invokedynamic}) runs.
     */
    static Optional<MethodSignature> lambdaTarget(Value value) {
        if (!(value instanceof JDynamicInvokeExpr dynamic)) {
            return Optional.empty();
        }
        return dynamic.getBootstrapArgs().stream().filter(MethodHandle.class::isInstance)
                .map(handle -> ((MethodHandle) handle).getReferenceSignature())
                .filter(MethodSignature.class::isInstance).map(MethodSignature.class::cast).findFirst();
    }

    /**
     * Decision 0065: what the method decides, reduced from its body when AuthTracer can, else custom; either way
     * decided by it.
     */
    private Requirement decided(JavaSootMethod method, String expression) {
        CodeRef code = MethodNames.codeRef(method.getSignature());
        DecisionBodies.Reading reading = readings.computeIfAbsent(code, key -> DecisionBodies.read(context, method));
        methods.putIfAbsent(code, method);
        return reading.requirement().map(requirement -> requirement.withSource(expression).decidedBy(code))
                .orElseGet(() -> Requirement.custom(expression, code));
    }

    /**
     * The decision methods this scan resolved that decide parts of the requirement.
     */
    @Supports(Feature.SERVICE_CALLS)
    List<JavaSootMethod> deciders(Requirement requirement) {
        Map<CodeRef, Requirement.Kind> codes = new LinkedHashMap<>();
        decisions(requirement, codes);
        return codes.keySet().stream().map(methods::get).filter(Objects::nonNull).toList();
    }

    /**
     * Whether what the code decides is re-read from a store or another service on every call (SRC-14).
     */
    boolean live(CodeRef code) {
        DecisionBodies.Reading reading = readings.get(code);
        return reading != null && (!reading.reads().isEmpty() || !reading.calls().isEmpty());
    }

    /**
     * OAUTH-04: {@code @oauth2.hasScope('x')} on a {@code DefaultOAuth2AuthorizationManagerFactory} bean is
     * {@code SCOPE_x} (its {@code setScopePrefix}), with the factors of the multi-factor factory it wraps; an
     * {@code AuthorizationManagerFactory} bean's {@code hasRole('X')} is its prefix's role.
     */
    private Optional<Requirement> providedMethods(Bean bean, String methodName, List<String> literals,
            String expression) {
        boolean oauth2 = SpringBeans.assignable(context, bean.type(), Set.of(OAUTH2_FACTORY));
        boolean factory = SpringBeans.assignable(context, bean.type(), Set.of(MANAGER_FACTORY));
        if (!oauth2 && !factory || context.isApplication(bean.type()) || literals.contains(null)) {
            return Optional.empty();
        }
        String prefix = oauth2 ? "SCOPE_" : "ROLE_";
        if (bean.factory() != null) {
            for (Stmt stmt : bean.factory().getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                String setter = oauth2 ? "setScopePrefix" : "setRolePrefix";
                String owner = oauth2 ? DEFAULT_OAUTH2_FACTORY : DEFAULT_MANAGER_FACTORY;
                if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals(setter)
                        && invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName().equals(owner)
                        && invoke.get().getArgCount() == 1) {
                    if (!(invoke.get().getArg(0) instanceof StringConstant constant)) {
                        return Optional.empty();
                    }
                    prefix = constant.getValue();
                }
            }
        }
        List<BuiltInManagers.Arg> args = literals.stream().map(text -> (BuiltInManagers.Arg)
                new BuiltInManagers.Text(text)).toList();
        Requirement built = oauth2 ? BuiltInManagers.scopes(methodName, args, prefix)
                : BuiltInManagers.named(methodName, args, new SpelRequirements(prefix)).orElse(null);
        if (built == null) {
            return Optional.empty();
        }
        Requirement read = built.withSource(expression);
        Optional<Requirement> factors = bean.factory() == null ? Optional.empty()
                : MultiFactor.built(context, bean.factory());
        Requirement required = factors.map(additional -> MultiFactor.require(read, additional)).orElse(read);
        return Optional.of(bean.factory() == null ? required
                : required.decidedBy(MethodNames.codeRef(bean.factory().getSignature())));
    }

    private boolean isManager(ClassType type) {
        return SpringBeans.assignable(context, type, MANAGERS);
    }

    /**
     * The manager's {@code authorize} method, its own or one it inherits.
     */
    private Optional<JavaSootMethod> authorizeMethod(ClassType type) {
        return method(type, "authorize", 2);
    }

    /**
     * The method of the class (or one it inherits) with the name that takes as many parameters as the call passes,
     * or the only one of the name when it is varargs, over whose last parameter SpEL spreads the call's arguments
     * ({@code @rules.anyRole(#root, 'A', 'B')}); not a bridge, not abstract. An overload of another arity is another
     * method: one a library superclass declares is not read.
     */
    private Optional<JavaSootMethod> method(ClassType type, String name, int arguments) {
        List<ClassType> types = new ArrayList<>(List.of(type));
        types.addAll(context.superClassesOf(type));
        for (ClassType candidate : types) {
            Optional<JavaSootClass> cls = context.findClass(candidate).filter(found -> context.isApplication(
                    found.getType()));
            if (cls.isEmpty()) {
                continue;
            }
            List<JavaSootMethod> named = cls.get().getMethods().stream().filter(method -> method.getName()
                    .equals(name) && method.hasBody() && !MethodModifier.isBridge(method.getModifiers())).toList();
            Optional<JavaSootMethod> exact = named.stream().filter(method -> method.getParameterCount() == arguments)
                    .findFirst();
            if (exact.isPresent()) {
                return exact;
            }
            if (named.size() == 1 && MethodModifier.isVarargs(named.getFirst().getModifiers())) {
                return Optional.of(named.getFirst());
            }
        }
        return Optional.empty();
    }

    /**
     * {@code @Bean} names: its {@code name} (or {@code value}) attribute, else the method's name.
     */
    private List<String> beanNames(JavaSootMethod method) {
        Optional<AnnotationUsage> annotation = context.findAnnotation(method, SpringNames.BEAN);
        List<String> names = new ArrayList<>();
        annotation.ifPresent(found -> {
            names.addAll(Annotations.strings(found, "name"));
            names.addAll(Annotations.strings(found, "value"));
        });
        return names.isEmpty() ? List.of(method.getName()) : names;
    }

    /**
     * The class a bean method creates, when every return is a {@code new} of the same class.
     */
    private static Optional<ClassType> created(JavaSootMethod method) {
        Set<ClassType> types = new LinkedHashSet<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned) {
                Optional<ClassType> type = returned.getOp() instanceof Local local
                        ? Locals.definition(method.getBody(), local).filter(JNewExpr.class::isInstance)
                                .map(value -> ((JNewExpr) value).getType()) : Optional.empty();
                if (type.isEmpty()) {
                    return Optional.empty();
                }
                types.add(type.get());
            }
        }
        return types.size() == 1 ? Optional.of(types.iterator().next()) : Optional.empty();
    }
}
