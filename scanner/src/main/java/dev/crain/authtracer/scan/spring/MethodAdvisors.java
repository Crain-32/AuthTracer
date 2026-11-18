package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractBinopExpr;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JAddExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.expr.JSubExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.JavaSootMethod;

/**
 * Method-security interceptors published as beans. METHOD-12: {@code AuthorizationManagerBeforeMethodInterceptor
 * .preAuthorize()} and its siblings turn an annotation on even with its {@code @EnableMethodSecurity} flag off.
 * AUTHZ-02: given an {@code AuthorizationManager}, that manager decides instead of the annotation's own
 * attributes. METHOD-11: {@code new AuthorizationManagerBeforeMethodInterceptor(pointcut, manager)} guards every
 * bean method its {@code AspectJExpressionPointcut} matches. Orders as Spring Security 7.1.1 sets them.
 */
@Supports(Feature.METHOD_SECURITY)
final class MethodAdvisors {

    private static final String PACKAGE = "org.springframework.security.authorization.method.";
    /**
     * RX-07: the reactive interceptors take the same factory calls and constructors.
     */
    private static final Set<String> BEFORE = Set.of(PACKAGE + "AuthorizationManagerBeforeMethodInterceptor",
            PACKAGE + "AuthorizationManagerBeforeReactiveMethodInterceptor");
    private static final Set<String> AFTER = Set.of(PACKAGE + "AuthorizationManagerAfterMethodInterceptor",
            PACKAGE + "AuthorizationManagerAfterReactiveMethodInterceptor");
    private static final String ASPECTJ_POINTCUT = "org.springframework.aop.aspectj.AspectJExpressionPointcut";
    private static final String INTERCEPTORS_ORDER = PACKAGE + "AuthorizationInterceptorsOrder";
    private static final String ROLE = "org.springframework.context.annotation.Role";
    /**
     * An array element that is neither a constant nor a manager.
     */
    private static final Object UNREAD = new Object();
    private static final String DENIED_HANDLER = PACKAGE + "MethodAuthorizationDeniedHandler";

    /**
     * Spring Security's own managers: an advisor built with one keeps the annotation's meaning.
     */
    private static final Map<String, String> DEFAULT_MANAGERS = Map.of(
            PACKAGE + "PreAuthorizeAuthorizationManager", SpringNames.PRE_AUTHORIZE,
            PACKAGE + "PostAuthorizeAuthorizationManager", SpringNames.POST_AUTHORIZE,
            PACKAGE + "PreAuthorizeReactiveAuthorizationManager", SpringNames.PRE_AUTHORIZE,
            PACKAGE + "PostAuthorizeReactiveAuthorizationManager", SpringNames.POST_AUTHORIZE,
            PACKAGE + "SecuredAuthorizationManager", SpringNames.SECURED,
            PACKAGE + "Jsr250AuthorizationManager", SpringNames.ROLES_ALLOWED);

    /**
     * The interceptors' static factories (the only methods of theirs with these names) and the annotation each reads.
     */
    private static final Map<String, String> FACTORIES = Map.of("preAuthorize", SpringNames.PRE_AUTHORIZE,
            "postAuthorize", SpringNames.POST_AUTHORIZE, "secured", SpringNames.SECURED,
            "jsr250", SpringNames.ROLES_ALLOWED);

    private static final Map<String, String> FILTER_INTERCEPTORS = Map.of(
            PACKAGE + "PreFilterAuthorizationMethodInterceptor", SpringNames.PRE_FILTER,
            PACKAGE + "PostFilterAuthorizationMethodInterceptor", SpringNames.POST_FILTER,
            PACKAGE + "PreFilterAuthorizationReactiveMethodInterceptor", SpringNames.PRE_FILTER,
            PACKAGE + "PostFilterAuthorizationReactiveMethodInterceptor", SpringNames.POST_FILTER);

    /**
     * Default interceptor orders ({@code AuthorizationInterceptorsOrder}), before any {@code offset}.
     */
    static final Map<String, Integer> ORDERS = Map.of(
            SpringNames.PRE_FILTER, 100, SpringNames.PRE_AUTHORIZE, 200, SpringNames.SECURED, 300,
            SpringNames.ROLES_ALLOWED, 400, SpringNames.PERMIT_ALL, 400, SpringNames.DENY_ALL, 400,
            SpringNames.POST_AUTHORIZE, 500, SpringNames.POST_FILTER, 600);

    /**
     * An annotation an advisor bean turns on.
     *
     * @param custom the requirement of a custom manager, which replaces the annotation's; {@code null} keeps it
     * @param handler DENY-04: the custom manager's class when it is also a {@code MethodAuthorizationDeniedHandler},
     *        which then handles the denials, else {@code null}
     * @param order decision 0092: the interceptor's order, its annotation's default unless {@code setOrder(..)}
     *        changes it
     * @param hierarchy decision 0092: the custom manager is given the RoleHierarchy ({@code setRoleHierarchy(..)})
     */
    record AnnotationAdvisor(String annotation, Requirement custom, JavaSootMethod bean, String handler, int order,
            boolean hierarchy) {
    }

    /**
     * METHOD-11: a pointcut and the requirement its manager enforces on every matched method.
     *
     * @param handler as for {@link AnnotationAdvisor}
     * @param hierarchy as for {@link AnnotationAdvisor}
     */
    record PointcutAdvisor(Pointcuts.Pointcut pointcut, String expression, Requirement requirement, Phase phase,
            int order, JavaSootMethod bean, String handler, boolean hierarchy) {
    }

    private record PointcutValue(String expression) {
    }

    /**
     * Decision 0088: the annotation an interceptor reads when it is Spring's, built with its defaults:
     * {@code AuthorizationManagerBeforeMethodInterceptor.preAuthorize()} and its siblings without a manager, or
     * {@code new PreFilterAuthorizationMethodInterceptor()} and the other filter interceptors.
     */
    static Optional<String> defaultInterceptor(Value value) {
        if (value instanceof JNewExpr created) {
            return Optional.ofNullable(FILTER_INTERCEPTORS.get(created.getType().getFullyQualifiedName()));
        }
        if (value instanceof AbstractInvokeExpr call && !(call instanceof AbstractInstanceInvokeExpr)
                && call.getArgCount() == 0) {
            String owner = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
            return BEFORE.contains(owner) || AFTER.contains(owner)
                    ? Optional.ofNullable(FACTORIES.get(call.getMethodSignature().getName())) : Optional.empty();
        }
        return Optional.empty();
    }

    /**
     * @param handler the manager's class when it is a {@code MethodAuthorizationDeniedHandler}
     * @param hierarchy the code gave it the RoleHierarchy, which Spring's factories' managers don't have
     */
    private record ManagerValue(Requirement requirement, String annotation, String handler, boolean hierarchy) {

        ManagerValue(Requirement requirement, String annotation) {
            this(requirement, annotation, null, false);
        }

        ManagerValue(Requirement requirement, String annotation, String handler) {
            this(requirement, annotation, handler, false);
        }
    }

    private record Interceptor(String annotation, Requirement custom, PointcutValue pointcut,
            Requirement requirement, Phase phase, int[] order, String handler, boolean hierarchy) {

        Interceptor(String annotation, Requirement custom, PointcutValue pointcut, Requirement requirement,
                Phase phase, int[] order) {
            this(annotation, custom, pointcut, requirement, phase, order, null, false);
        }
    }

    /**
     * Advisor and interceptor types: a bean method returning one is a method-security advisor when it, or a helper
     * of the application's it calls, builds one of Spring Security's.
     */
    private static final Set<String> ADVISOR_TYPES = Set.of("org.springframework.aop.Advisor",
            "org.aopalliance.intercept.MethodInterceptor");
    /**
     * How many helpers deep a bean method's advisor is followed.
     */
    private static final int HELPERS = 3;

    private final ScanContext context;
    private final GraphBuilder graph;
    private final Pointcuts pointcuts;
    private final List<AnnotationAdvisor> annotations = new ArrayList<>();
    private final List<PointcutAdvisor> advisors = new ArrayList<>();
    private int helpers;

    /**
     * @param methodSecurity whether {@code @EnableMethodSecurity} registers its auto-proxy creator
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    MethodAdvisors(ScanContext context, GraphBuilder graph, boolean methodSecurity) {
        this.context = context;
        this.graph = graph;
        this.pointcuts = new Pointcuts(context);
        // Decision 0092: spring.aop.auto=false turns Spring Boot's auto-proxy creator off.
        boolean boot = AutoProxyCreators.boot(context);
        boolean aspectJ = AutoProxyCreators.aspectJ(context);
        for (JavaSootMethod method : SpringBeans.beanMethods(context)) {
            if (!method.hasBody()) {
                continue;
            }
            Optional<Interceptor> interceptor = read(method);
            if (interceptor.isPresent()) {
                add(method, interceptor.get(), aspectJ, methodSecurity, boot);
            }
            else if (unreadAdvisor(method)) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The method-security advisor bean "
                        + MethodNames.key(method.getSignature()) + " builds an advisor AuthTracer can't read: the"
                        + " methods it guards show no check for it", MethodNames.codeRef(method.getSignature())));
            }
        }
    }

    /**
     * Decision 0092: a bean method returning an advisor or interceptor that it, or a helper it calls, builds from
     * Spring Security's method-security classes, though AuthTracer read none from it. One that creates an
     * application class is an {@code AuthorizationAdvisor} of the application's own ({@link CustomAdvisors}).
     */
    private boolean unreadAdvisor(JavaSootMethod method) {
        if (!(method.getReturnType() instanceof ClassType returned)
                || !SpringBeans.assignable(context, returned, ADVISOR_TYPES)) {
            return false;
        }
        List<JavaSootMethod> code = new ArrayList<>(List.of(method));
        method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> context.isApplication(invoke.getMethodSignature().getDeclClassType()))
                .flatMap(invoke -> context.findMethod(invoke.getMethodSignature()).stream())
                .filter(JavaSootMethod::hasBody).forEach(code::add);
        boolean security = false;
        for (JavaSootMethod each : code) {
            for (Stmt stmt : each.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition && definition.getRightOp() instanceof JNewExpr
                        created && context.isApplication(created.getType())) {
                    return false;
                }
                security |= Locals.invoke(stmt).filter(invoke -> invoke.getMethodSignature().getDeclClassType()
                        .getFullyQualifiedName().startsWith(PACKAGE)).isPresent();
            }
        }
        return security;
    }

    List<AnnotationAdvisor> annotations() {
        return annotations;
    }

    List<PointcutAdvisor> pointcutAdvisors() {
        return advisors;
    }

    /**
     * {@code @EnableMethodSecurity}'s auto-proxy creator only applies advisor beans with the infrastructure role, and
     * so does the one Spring Boot registers without AspectJ (4.1.1 {@code AopAutoConfiguration
     * .ClassProxyingConfiguration}); an AspectJ auto-proxy creator (Spring Boot's, with AspectJ on the classpath)
     * applies them all.
     */
    @Supports({Feature.FINDING_NOT_ENFORCED, Feature.FINDING_OPAQUE_CONFIG})
    private void add(JavaSootMethod bean, Interceptor interceptor, boolean aspectJ, boolean methodSecurity,
            boolean boot) {
        boolean infrastructure = context.findAnnotation(bean, ROLE)
                .flatMap(role -> Annotations.integer(role, "value"))
                .filter(role -> role == 2).isPresent();
        if (!aspectJ && !(infrastructure && (methodSecurity || boot))) {
            graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, "The method-security advisor bean "
                    + MethodNames.key(bean.getSignature()) + " never runs: " + (methodSecurity || boot
                            ? "without @Role(BeanDefinition.ROLE_INFRASTRUCTURE) " + (methodSecurity
                                    ? "@EnableMethodSecurity's" : "Spring Boot's") + " auto-proxy creator ignores it"
                            : "nothing auto-proxies beans (no @EnableMethodSecurity or AspectJ auto-proxying"
                                    + AutoProxyCreators.bootOff(context) + ")"),
                    MethodNames.codeRef(bean.getSignature())));
            return;
        }
        Requirement manager = interceptor.annotation() != null ? interceptor.custom() : interceptor.requirement();
        if (manager != null && manager.kind() == Requirement.Kind.EXPRESSION && manager.decidedBy() == null) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The method-security advisor bean "
                    + MethodNames.key(bean.getSignature()) + " is given a manager AuthTracer can't read ("
                    + manager.expression() + "): the methods it guards show it as an opaque requirement",
                    MethodNames.codeRef(bean.getSignature())));
        }
        if (interceptor.annotation() != null) {
            annotations.add(new AnnotationAdvisor(interceptor.annotation(), interceptor.custom(), bean,
                    interceptor.handler(), interceptor.order()[0], interceptor.hierarchy()));
            return;
        }
        Optional<Pointcuts.Pointcut> pointcut = interceptor.pointcut() == null || interceptor.pointcut()
                .expression() == null ? Optional.empty() : pointcuts.parse(interceptor.pointcut().expression());
        if (pointcut.isEmpty()) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The method-security advisor bean "
                    + MethodNames.key(bean.getSignature()) + " uses a pointcut AuthTracer can't read"
                    + (interceptor.pointcut() != null && interceptor.pointcut().expression() != null
                            ? " (" + interceptor.pointcut().expression() + ")" : "")
                    + "; the methods it guards show no check for it", MethodNames.codeRef(bean.getSignature())));
            return;
        }
        advisors.add(new PointcutAdvisor(pointcut.get(), interceptor.pointcut().expression(),
                interceptor.requirement(), interceptor.phase(), interceptor.order()[0], bean, interceptor.handler(),
                interceptor.hierarchy()));
    }

    /**
     * Interprets one bean method; empty when it doesn't return a method-security interceptor.
     */
    private Optional<Interceptor> read(JavaSootMethod method) {
        return interpret(method, Map.of()) instanceof Interceptor interceptor ? Optional.of(interceptor)
                : Optional.empty();
    }

    /**
     * What the method returns, as far as AuthTracer reads it.
     *
     * @param arguments decision 0092: what a helper is handed, by parameter; a bean method's parameters are beans
     */
    private Object interpret(JavaSootMethod method, Map<Integer, Object> arguments) {
        Map<Local, Object> values = new HashMap<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt ret) {
                return ret.getOp() instanceof Local local ? values.get(local) : null;
            }
            if (stmt instanceof AbstractDefinitionStmt definition) {
                Value right = definition.getRightOp();
                if (definition.getLeftOp() instanceof JArrayRef array
                        && values.get(array.getBase()) instanceof List<?> list) {
                    Object element = right instanceof Local local ? values.get(local) : null;
                    addTo(list, Locals.text(right, values).map(Object.class::cast)
                            .orElse(element instanceof ManagerValue manager ? manager : UNREAD));
                }
                else if (definition.getLeftOp() instanceof Local local) {
                    Object value = right instanceof JParameterRef parameter
                            ? arguments.containsKey(parameter.getIndex()) ? arguments.get(parameter.getIndex())
                                    : injected(method.getParameterType(parameter.getIndex()), method.getBody()
                                            .getParameterLocal(parameter.getIndex()).getName())
                            : evaluate(right, values);
                    if (value != null) {
                        values.put(local, value);
                    }
                }
            }
            else if (stmt.isInvokableStmt()) {
                stmt.asInvokableStmt().getInvokeExpr().ifPresent(invoke -> sideEffect(invoke, values));
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static void addTo(List<?> list, Object element) {
        ((List<Object>) list).add(element);
    }

    @Supports(Feature.CUSTOM_DECISIONS)
    private Object evaluate(Value right, Map<Local, Object> values) {
        if (right instanceof StringConstant constant) {
            return constant.getValue();
        }
        if (right instanceof Local local) {
            return values.get(local);
        }
        if (right instanceof JNewArrayExpr) {
            return new ArrayList<>();
        }
        if (right instanceof JStaticFieldRef field
                && field.getFieldSignature().getDeclClassType().getFullyQualifiedName().equals(INTERCEPTORS_ORDER)) {
            return field.getFieldSignature().getName();
        }
        if (right instanceof JNewExpr created) {
            String type = created.getType().getFullyQualifiedName();
            if (type.equals(ASPECTJ_POINTCUT)) {
                return new PointcutValue(null);
            }
            if (DEFAULT_MANAGERS.containsKey(type)) {
                return new ManagerValue(null, DEFAULT_MANAGERS.get(type));
            }
            if (FILTER_INTERCEPTORS.containsKey(type)) {
                String annotation = FILTER_INTERCEPTORS.get(type);
                return new Interceptor(annotation, null, null, null, null, new int[] {ORDERS.get(annotation)});
            }
            if (BEFORE.contains(type) || AFTER.contains(type)) {
                return type;
            }
            if (!context.isApplication(created.getType())) {
                return null;
            }
            String what = "custom AuthorizationManager " + MethodNames.simpleName(type);
            return new ManagerValue(DecisionCode.of(context).created(created.getType(), what)
                    .orElse(Requirement.expression(what)), null, handler(created.getType()));
        }
        // AUTHZ-02: a lambda or method reference as the manager.
        Optional<MethodSignature> lambda = DecisionCode.lambdaTarget(right)
                .filter(target -> context.isApplication(target.getDeclClassType())
                        && DecisionCode.isManagerLambda(target));
        if (lambda.isPresent()) {
            return new ManagerValue(DecisionCode.of(context).lambda(lambda.get(), "custom AuthorizationManager "
                    + lambda.get().getName()), null);
        }
        if (right instanceof JFieldRef field) {
            return injected(field.getFieldSignature().getType(), field.getFieldSignature().getName());
        }
        if (right instanceof AbstractInvokeExpr invoke) {
            return call(invoke, values);
        }
        // An order relative to Spring's: AuthorizationInterceptorsOrder.SECURED.getOrder() + 1.
        if (right instanceof AbstractBinopExpr binop && (binop instanceof JAddExpr || binop instanceof JSubExpr)
                && Locals.evaluated(binop.getOp1(), values) instanceof Integer first
                && Locals.evaluated(binop.getOp2(), values) instanceof Integer second) {
            return binop instanceof JAddExpr ? first + second : first - second;
        }
        return null;
    }

    private Object call(AbstractInvokeExpr invoke, Map<Local, Object> values) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = invoke.getMethodSignature().getName();
        List<Object> args = invoke.getArgs().stream().map(arg -> Locals.evaluated(arg, values)).toList();
        if ((BEFORE.contains(owner) || AFTER.contains(owner)) && FACTORIES.containsKey(name)) {
            String annotation = FACTORIES.get(name);
            ManagerValue manager = args.isEmpty() ? null : args.getFirst() instanceof ManagerValue value ? value
                    : new ManagerValue(Requirement.expression("AuthorizationManager"), null);
            Requirement custom = manager == null || manager.annotation() != null ? null : manager.requirement();
            return new Interceptor(annotation, custom, null, null, null, new int[] {ORDERS.get(annotation)},
                    manager == null ? null : manager.handler(), manager != null && manager.hierarchy());
        }
        if (BuiltInManagers.isFactoryClass(owner) && !(invoke instanceof AbstractInstanceInvokeExpr)) {
            return BuiltInManagers.factory(owner, name, invoke.getMethodSignature().getParameterTypes().stream()
                    .map(Object::toString).toList(), args.stream().map(MethodAdvisors::managerArg).toList())
                    .map(requirement -> new ManagerValue(requirement, null)).orElse(null);
        }
        if (owner.equals(INTERCEPTORS_ORDER) && name.equals("getOrder") && invoke instanceof AbstractInstanceInvokeExpr
                instance && values.get(instance.getBase()) instanceof String constant) {
            return switch (constant) {
                case "FIRST" -> Integer.MIN_VALUE;
                case "PRE_FILTER" -> 100;
                case "PRE_AUTHORIZE" -> 200;
                case "SECURED" -> 300;
                case "JSR250" -> 400;
                case "SECURE_RESULT" -> 450;
                case "POST_AUTHORIZE" -> 500;
                case "POST_FILTER" -> 600;
                default -> Integer.MAX_VALUE;
            };
        }
        // Decision 0092: a helper of the application's that builds the advisor, its manager or its pointcut.
        if (context.isApplication(invoke.getMethodSignature().getDeclClassType()) && helpers < HELPERS) {
            Optional<JavaSootMethod> helper = context.findMethod(invoke.getMethodSignature())
                    .filter(JavaSootMethod::hasBody);
            if (helper.isPresent()) {
                Map<Integer, Object> handed = new HashMap<>();
                for (int i = 0; i < args.size(); i++) {
                    if (args.get(i) != null) {
                        handed.put(i, args.get(i));
                    }
                }
                helpers++;
                try {
                    return interpret(helper.get(), handed);
                }
                finally {
                    helpers--;
                }
            }
        }
        return null;
    }

    /**
     * {@code pointcut.setExpression(..)}, {@code interceptor.setOrder(..)} and the advisor constructors.
     */
    private void sideEffect(AbstractInvokeExpr invoke, Map<Local, Object> values) {
        if (!(invoke instanceof AbstractInstanceInvokeExpr instance)) {
            return;
        }
        String name = invoke.getMethodSignature().getName();
        Object receiver = values.get(instance.getBase());
        List<Object> args = invoke.getArgs().stream().map(arg -> Locals.evaluated(arg, values)).toList();
        if (receiver instanceof PointcutValue && name.equals("setExpression") && args.getFirst() instanceof String text) {
            values.put(instance.getBase(), new PointcutValue(text));
        }
        else if (receiver instanceof ManagerValue manager && name.equals("setRoleHierarchy")) {
            // Decision 0092: a manager built here and given the RoleHierarchy is widened by it.
            values.put(instance.getBase(), new ManagerValue(manager.requirement(), manager.annotation(),
                    manager.handler(), true));
        }
        else if (receiver instanceof Interceptor interceptor && name.equals("setOrder")) {
            if (invoke.getArg(0) instanceof IntConstant constant) {
                interceptor.order()[0] = constant.getValue();
            }
            else if (args.getFirst() instanceof Integer order) {
                interceptor.order()[0] = order;
            }
        }
        else if (receiver instanceof String type && name.equals("<init>") && args.size() == 2) {
            PointcutValue pointcut = args.get(0) instanceof PointcutValue value ? value : null;
            Requirement requirement = args.get(1) instanceof ManagerValue manager && manager.requirement() != null
                    ? manager.requirement() : Requirement.expression("AuthorizationManager");
            boolean before = BEFORE.contains(type);
            // The constructors leave the order at FIRST (before), 0 (after) and LAST (reactive after).
            int order = before ? Integer.MIN_VALUE : type.contains("Reactive") ? Integer.MAX_VALUE : 0;
            ManagerValue manager = args.get(1) instanceof ManagerValue value ? value : null;
            values.put(instance.getBase(), new Interceptor(null, null, pointcut, requirement,
                    before ? Phase.PRE : Phase.POST, new int[] {order}, manager == null ? null : manager.handler(),
                    manager != null && manager.hierarchy()));
        }
    }

    /**
     * Decision 0064 (AUTHZ-02): a custom manager the advisor bean method is handed or reads from a field, by its type
     * or the one bean of a manager type; {@code null} when it isn't one.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    private ManagerValue injected(Type type, String name) {
        String what = "custom AuthorizationManager " + (type instanceof ClassType classType
                ? MethodNames.simpleName(classType.getFullyQualifiedName()) : name);
        return DecisionCode.of(context).injected(type, name, what).map(requirement -> new ManagerValue(requirement,
                null, type instanceof ClassType classType ? handler(classType) : null)).orElse(null);
    }

    /**
     * DENY-04: 7.1.1's interceptors hand a denial to the manager when it is a {@code MethodAuthorizationDeniedHandler}
     * ({@code AuthorizationManagerBeforeMethodInterceptor#handle}), else to their own throwing handler.
     */
    private String handler(ClassType type) {
        return context.isApplication(type) && SpringBeans.assignable(context, type, Set.of(DENIED_HANDLER))
                ? type.getFullyQualifiedName() : null;
    }

    /**
     * Decision 0063: an argument as the built-in managers' table reads it. A manager the advisor builds with one of
     * Spring's static factories has no RoleHierarchy, and {@code ROLE_} whatever {@code GrantedAuthorityDefaults} says.
     */
    private static BuiltInManagers.Arg managerArg(Object value) {
        if (value instanceof String text) {
            return new BuiltInManagers.Text(text);
        }
        if (value instanceof ManagerValue manager && manager.requirement() != null) {
            return new BuiltInManagers.Manager(manager.requirement());
        }
        if (value instanceof List<?> list && list.stream().anyMatch(ManagerValue.class::isInstance)) {
            List<Requirement> managers = list.stream().filter(element -> element instanceof ManagerValue manager
                    && manager.requirement() != null).map(element -> ((ManagerValue) element).requirement()).toList();
            return new BuiltInManagers.Managers(managers, managers.size() == list.size());
        }
        if (value instanceof List<?> list) {
            List<String> texts = list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
            return new BuiltInManagers.Texts(texts, texts.size() == list.size());
        }
        return BuiltInManagers.UNKNOWN;
    }
}
