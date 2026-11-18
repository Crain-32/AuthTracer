package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.constant.NullConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.MethodModifier;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * EXPR-05 (decision 0091): the application's {@code MethodSecurityExpressionHandler} bean. Spring Security 7.1.1's
 * pre/post annotations use it instead of their own: {@code PrePostMethodSecurityConfiguration#setExpressionHandler}
 * gives it to the interceptors, while the {@code GrantedAuthorityDefaults}, {@code RoleHierarchy} and
 * {@code AuthorizationManagerFactory} beans go only to the handler it replaces. What the bean is set up with decides
 * the role prefix, the hierarchy and the factory; a subclass may bring a root of its own.
 */
@Supports({Feature.METHOD_SECURITY, Feature.REQUIREMENTS})
final class ExpressionHandlers {

    private static final String HANDLER =
            "org.springframework.security.access.expression.method.MethodSecurityExpressionHandler";
    private static final String DEFAULT_HANDLER =
            "org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler";
    private static final String OPERATIONS =
            "org.springframework.security.access.expression.SecurityExpressionOperations";
    private static final String MANAGER_FACTORY =
            "org.springframework.security.authorization.AuthorizationManagerFactory";
    private static final String SUPPLIER = "java.util.function.Supplier";
    private static final String DEFAULT_PREFIX = "ROLE_";
    /**
     * What sets up how a root checks roles and authentication.
     */
    private static final Set<String> ROOT_SETUP = Set.of("setDefaultRolePrefix", "setRoleHierarchy",
            "setAuthorizationManagerFactory", "setTrustResolver");

    /**
     * The handler bean as pre/post expressions see it.
     *
     * @param factory the role prefix, hierarchy and additional factors the handler's factory builds with
     * @param strippedPrefix what the root takes off a role before the factory adds its prefix: the handler's
     *        {@code setDefaultRolePrefix(..)}
     * @param root the expression root of a subclass's own, whose methods expressions may call; {@code null} for
     *        Spring's
     * @param rootIgnored the subclass makes its root in {@code createSecurityExpressionRoot(Authentication,
     *        MethodInvocation)}, which the annotations never call
     */
    record Handler(AuthorizationManagerFactories.Factory factory, String strippedPrefix, ClassType root,
            boolean rootIgnored) {
    }

    private ExpressionHandlers() {
    }

    /**
     * @param roleHierarchy the {@code RoleHierarchy} bean, for a handler that is handed it
     * @param factoryBean the {@code AuthorizationManagerFactory} bean's, for a handler that is handed it
     * @param legacy {@code @EnableGlobalMethodSecurity}, whose interceptors call {@code createSecurityExpressionRoot}
     */
    static Optional<Handler> detect(ScanContext context, GraphBuilder graph,
            RoleHierarchies roleHierarchy, Optional<AuthorizationManagerFactories.Factory> factoryBean,
            boolean legacy) {
        for (JavaSootMethod method : SpringBeans.beanMethods(context)) {
            if (method.hasBody() && method.getReturnType() instanceof ClassType returned
                    && isHandler(context, returned)) {
                return Optional.of(handler(context, graph, withHelpers(context, List.of(method)),
                        createdHandler(context, method).orElse(returned), roleHierarchy, factoryBean, legacy));
            }
        }
        // A handler class that is a component sets itself up in its constructor.
        for (JavaSootClass cls : context.applicationClasses()) {
            if (isHandler(context, cls.getType()) && context.hasAnnotation(cls, SpringNames.COMPONENT)) {
                List<JavaSootMethod> setup = cls.getMethods().stream().filter(method -> method.getName()
                        .equals("<init>") && method.hasBody()).toList();
                return Optional.of(handler(context, graph, withHelpers(context, setup), cls.getType(), roleHierarchy,
                        factoryBean, legacy));
            }
        }
        return Optional.empty();
    }

    private static Handler handler(ScanContext context, GraphBuilder graph, List<JavaSootMethod> setup,
            ClassType type, RoleHierarchies roleHierarchy, Optional<AuthorizationManagerFactories.Factory> factoryBean,
            boolean legacy) {
        String prefix = "ROLE_";
        RoleHierarchies hierarchy = RoleHierarchies.NONE;
        AuthorizationManagerFactories.Factory factory = null;
        for (JavaSootMethod method : setup) {
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt).filter(call -> call.getArgCount() == 1);
                if (invoke.isEmpty() || !isHandler(context, invoke.get().getMethodSignature().getDeclClassType())) {
                    continue;
                }
                switch (invoke.get().getMethodSignature().getName()) {
                    case "setDefaultRolePrefix" -> {
                        if (invoke.get().getArg(0) instanceof StringConstant constant) {
                            prefix = constant.getValue();
                        }
                        else if (invoke.get().getArg(0) instanceof NullConstant) {
                            // 7.1.1: a null prefix is no prefix.
                            prefix = "";
                        }
                        else {
                            opaque(graph, method, "does not set its role prefix from a constant; pre/post role checks"
                                    + " are shown with ROLE_");
                        }
                    }
                    case "setRoleHierarchy" -> hierarchy = AuthorizationManagerFactories.hierarchyArgument(context,
                            graph, method, invoke.get(), roleHierarchy, "The MethodSecurityExpressionHandler bean ");
                    case "setAuthorizationManagerFactory" -> {
                        factory = givenFactoryBean(method, invoke.get()) ? factoryBean.orElse(null) : null;
                        if (factory == null) {
                            opaque(graph, method, "is given an AuthorizationManagerFactory AuthTracer can't read;"
                                    + " pre/post rules are shown as the default factory builds them");
                        }
                    }
                    case "setTrustResolver" -> opaque(graph, method, "decides who is anonymous, remembered or fully"
                            + " authenticated with its own AuthenticationTrustResolver; pre/post authentication checks"
                            + " are shown as Spring's default resolver decides them");
                    default -> {
                    }
                }
            }
        }
        RootOverride root = root(context, graph, type, legacy);
        if (root != null && root.own()) {
            // Its expressions run on that root, which checks roles as a SecurityExpressionRoot starts out (7.1.1):
            // ROLE_ and Spring's default factory, without the handler's prefix, hierarchy or factory.
            return new Handler(new AuthorizationManagerFactories.Factory(DEFAULT_PREFIX, RoleHierarchies.NONE),
                    DEFAULT_PREFIX, root.root(), false);
        }
        return new Handler(factory != null ? factory : new AuthorizationManagerFactories.Factory(prefix, hierarchy),
                prefix, root == null ? null : root.root(), root != null && root.ignored());
    }

    /**
     * @param ignored made where the annotations never ask for it
     * @param own made in {@code createEvaluationContext} and set up neither there nor in its constructors: it
     *        checks roles itself, as a root starts out
     */
    private record RootOverride(ClassType root, boolean ignored, boolean own) {
    }

    /**
     * A subclass's own root: what its {@code createEvaluationContext(Supplier, MethodInvocation)} sets (an
     * OPAQUE_CONFIG: the context it makes is its own), or what its {@code createSecurityExpressionRoot(Authentication,
     * MethodInvocation)} makes, which only the legacy interceptors call: 7.1.1's
     * {@code DefaultMethodSecurityExpressionHandler#createEvaluationContext(Supplier, MethodInvocation)} makes its
     * root in a private method.
     */
    @Supports({Feature.CUSTOM_DECISIONS, Feature.FINDING_NOT_ENFORCED, Feature.FINDING_OPAQUE_CONFIG})
    private static RootOverride root(ScanContext context, GraphBuilder graph, ClassType type, boolean legacy) {
        Optional<JavaSootClass> cls = type == null ? Optional.empty() : context.findClass(type)
                .filter(found -> context.isApplication(found.getType()));
        if (cls.isEmpty()) {
            return null;
        }
        Optional<JavaSootMethod> evaluation = declared(cls.get(), "createEvaluationContext", SUPPLIER);
        Optional<JavaSootMethod> rootMethod = declared(cls.get(), "createSecurityExpressionRoot",
                "org.springframework.security.core.Authentication");
        if (evaluation.isPresent()) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The MethodSecurityExpressionHandler "
                    + type.getFullyQualifiedName() + " makes the evaluation context of pre/post expressions itself"
                    + " (createEvaluationContext): the variables and root it gives them are its own",
                    MethodNames.codeRef(evaluation.get().getSignature())));
            return createdRoot(context, evaluation.get()).map(root -> new RootOverride(root, false,
                    !setsUpRoot(context, evaluation.get(), root))).orElse(null);
        }
        if (rootMethod.isPresent()) {
            Optional<ClassType> root = createdRoot(context, rootMethod.get());
            if (root.isPresent() && !legacy) {
                graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, "The MethodSecurityExpressionHandler "
                        + type.getFullyQualifiedName() + " makes its root " + MethodNames.simpleName(root.get()
                        .getFullyQualifiedName()) + " in createSecurityExpressionRoot(Authentication,"
                        + " MethodInvocation), which @EnableMethodSecurity's pre/post annotations never call (7.1.1 calls"
                        + " createEvaluationContext(Supplier, MethodInvocation)): an expression that calls one of its"
                        + " methods fails, so it denies every caller", MethodNames.codeRef(rootMethod.get()
                                .getSignature())));
            }
            return root.map(found -> new RootOverride(found, !legacy, false)).orElse(null);
        }
        return null;
    }

    /**
     * Whether the override, or the root's constructors, set up how the root checks roles and authentication
     * ({@code setDefaultRolePrefix}, {@code setRoleHierarchy}, ...), perhaps as the handler is.
     */
    private static boolean setsUpRoot(ScanContext context, JavaSootMethod evaluation, ClassType root) {
        List<JavaSootMethod> code = new ArrayList<>(List.of(evaluation));
        context.findClass(root).ifPresent(cls -> cls.getMethods().stream()
                .filter(method -> method.getName().equals("<init>") && method.hasBody()).forEach(code::add));
        for (JavaSootMethod method : code) {
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isPresent() && ROOT_SETUP.contains(invoke.get().getMethodSignature().getName())
                        && SpringBeans.assignable(context, invoke.get().getMethodSignature().getDeclClassType(),
                                Set.of(OPERATIONS))) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * The class's own override with the name whose first parameter is of the type.
     */
    private static Optional<JavaSootMethod> declared(JavaSootClass cls, String name, String firstParameter) {
        return cls.getMethods().stream().filter(method -> method.getName().equals(name) && method.hasBody()
                && !MethodModifier.isBridge(method.getModifiers()) && method.getParameterCount() == 2
                && method.getParameterType(0).toString().equals(firstParameter)).findFirst();
    }

    /**
     * The application's expression root the method creates.
     */
    private static Optional<ClassType> createdRoot(ScanContext context, JavaSootMethod method) {
        List<ClassType> roots = new ArrayList<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getRightOp() instanceof JNewExpr created
                    && context.isApplication(created.getType())
                    && SpringBeans.assignable(context, created.getType(), Set.of(OPERATIONS))) {
                roots.add(created.getType());
            }
        }
        return roots.size() == 1 ? Optional.of(roots.getFirst()) : Optional.empty();
    }

    /**
     * The handler class a bean method creates, when it is one of the application's.
     */
    private static Optional<ClassType> createdHandler(ScanContext context, JavaSootMethod method) {
        return method.getBody().getStmts().stream().filter(AbstractDefinitionStmt.class::isInstance)
                .map(stmt -> ((AbstractDefinitionStmt) stmt).getRightOp()).filter(JNewExpr.class::isInstance)
                .map(value -> ((JNewExpr) value).getType())
                .filter(created -> context.isApplication(created) && isHandler(context, created)).findFirst();
    }

    /**
     * Whether {@code setAuthorizationManagerFactory(factory)} is handed the {@code AuthorizationManagerFactory} bean,
     * a parameter of the bean method.
     */
    private static boolean givenFactoryBean(JavaSootMethod method, AbstractInvokeExpr setter) {
        return setter.getArg(0) instanceof Local argument && Locals.definition(method.getBody(), argument)
                .filter(JParameterRef.class::isInstance)
                .filter(parameter -> method.getParameterType(((JParameterRef) parameter).getIndex())
                        instanceof ClassType type && type.getFullyQualifiedName().equals(MANAGER_FACTORY))
                .isPresent();
    }

    /**
     * The setup methods, then the application helpers they hand the handler to or get it from.
     */
    private static List<JavaSootMethod> withHelpers(ScanContext context, List<JavaSootMethod> setup) {
        List<JavaSootMethod> all = new ArrayList<>(setup);
        for (JavaSootMethod method : setup) {
            AuthorizationManagerFactories.helpers(context, method, type -> isHandler(context, type)).stream()
                    .filter(helper -> !all.contains(helper)).forEach(all::add);
        }
        return all;
    }

    private static boolean isHandler(ScanContext context, ClassType type) {
        return SpringBeans.assignable(context, type, Set.of(HANDLER, DEFAULT_HANDLER));
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private static void opaque(GraphBuilder graph, JavaSootMethod method, String what) {
        graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The MethodSecurityExpressionHandler bean "
                + MethodNames.key(method.getSignature()) + " " + what, MethodNames.codeRef(method.getSignature())));
    }
}
