package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * ROLE-04: an {@code AuthorizationManagerFactory} bean (AUTHZ-06). When there is one, Spring Security 7.1.1 builds
 * the {@code authorizeHttpRequests} DSL's managers with it ({@code AuthorizeHttpRequestsConfigurer
 * #getAuthorizationManagerFactory}: a {@code <RequestAuthorizationContext>} bean, else an {@code <Object>} one), and
 * so do the pre/post SpEL built-ins ({@code PrePostMethodSecurityConfiguration} autowires a {@code <MethodInvocation>}
 * one). Either way the factory replaces the {@code RoleHierarchy} bean for those checks, and for the DSL the
 * {@code GrantedAuthorityDefaults} one too; pre/post keeps a {@code GrantedAuthorityDefaults} prefix other than
 * {@code ROLE_}, which {@code DefaultMethodSecurityExpressionHandler} sets on the factory through each root's
 * {@code setDefaultRolePrefix}. {@code @Secured} and JSR-250 never use it. A bean declared with a type variable
 * ({@code <T> AuthorizationManagerFactory<T>}) or raw serves both.
 *
 * @param http the factory {@code authorizeHttpRequests} uses, if any
 * @param prePost the factory pre/post method security uses, if any
 */
@Supports(Feature.REQUIREMENTS)
record AuthorizationManagerFactories(Optional<Factory> http, Optional<Factory> prePost) {

    private static final String FACTORY = "org.springframework.security.authorization.AuthorizationManagerFactory";
    private static final String DEFAULT_FACTORY =
            "org.springframework.security.authorization.DefaultAuthorizationManagerFactory";
    private static final String REQUEST_CONTEXT =
            "org.springframework.security.web.access.intercept.RequestAuthorizationContext";
    private static final String METHOD_INVOCATION = "org.aopalliance.intercept.MethodInvocation";
    private static final String ROLE_HIERARCHY = "org.springframework.security.access.hierarchicalroles.RoleHierarchy";
    /**
     * How the findings about a factory bean begin.
     */
    private static final String FACTORY_BEAN = "The AuthorizationManagerFactory bean ";

    /**
     * What a {@code DefaultAuthorizationManagerFactory} bean sets: {@code ROLE_} and no hierarchy unless it says so.
     *
     * @param additional what it adds to every rule it builds ({@code setAdditionalAuthorization}, decision 0037),
     *        {@code null} for nothing
     */
    record Factory(String rolePrefix, RoleHierarchies hierarchy, Requirement additional) {

        Factory(String rolePrefix, RoleHierarchies hierarchy) {
            this(rolePrefix, hierarchy, null);
        }

        /**
         * A rule as this factory builds it.
         */
        Requirement build(Requirement rule) {
            return additional == null ? rule : MultiFactor.require(rule, additional);
        }
    }

    private record Bean(JavaSootMethod method, String typeArgument, Factory factory) {
    }

    /**
     * @param roleHierarchy the {@code RoleHierarchy} bean, for a factory that is handed it
     */
    static AuthorizationManagerFactories detect(ScanContext context, GraphBuilder graph, RoleHierarchies roleHierarchy) {
        List<Bean> beans = new ArrayList<>();
        for (JavaSootMethod method : SpringBeans.beanMethods(context, FACTORY, DEFAULT_FACTORY)) {
            if (method.hasBody()) {
                String argument = context.classFiles().genericReturnType(method.getSignature())
                        .filter(generic -> generic.arguments().size() == 1)
                        .map(generic -> generic.arguments().getFirst().name()).orElse("");
                Factory factory = read(context, graph, method, roleHierarchy);
                if (BeanConditions.of(context).maybe(method).isPresent()) {
                    // Decision 0111: a bean that may not be made, read the weaker way for each part: its hierarchy
                    // widens the rules, so it stays; the factors it adds may not be asked for.
                    factory = new Factory(factory.rolePrefix(), factory.hierarchy());
                }
                beans.add(new Bean(method, argument, factory));
            }
        }
        if (beans.isEmpty()) {
            // AUTHZ-07: @EnableMultiFactorAuthentication's raw factory serves both, with ROLE_ and no hierarchy.
            MultiFactor.annotated(context).ifPresent(additional -> beans.add(new Bean(null, "",
                    new Factory("ROLE_", RoleHierarchies.NONE, additional))));
        }
        return new AuthorizationManagerFactories(
                pick(beans, REQUEST_CONTEXT).or(() -> pick(beans, "java.lang.Object")).or(() -> pick(beans, null)),
                pick(beans, METHOD_INVOCATION).or(() -> pick(beans, null)));
    }

    /**
     * @param typeArgument {@code null} for a bean with a type variable or no type argument, which matches any
     */
    private static Optional<Factory> pick(List<Bean> beans, String typeArgument) {
        return beans.stream().filter(bean -> typeArgument == null ? !bean.typeArgument().contains(".")
                : bean.typeArgument().equals(typeArgument)).map(Bean::factory).findFirst();
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private static Factory read(ScanContext context, GraphBuilder graph, JavaSootMethod method,
            RoleHierarchies roleHierarchy) {
        String prefix = "ROLE_";
        RoleHierarchies hierarchy = RoleHierarchies.NONE;
        // AUTHZ-08: AuthorizationManagerFactories.multiFactor()...build().
        Requirement additional = MultiFactor.built(context, method).orElse(null);
        // The bean method, then the helpers it hands the factory to or gets it from.
        List<JavaSootMethod> setup = new ArrayList<>(List.of(method));
        setup.addAll(helpers(context, method, type -> Set.of(FACTORY, DEFAULT_FACTORY)
                .contains(type.getFullyQualifiedName())));
        for (JavaSootMethod each : setup) {
            List<Local> requiredAuthorities = new ArrayList<>();
            for (Stmt stmt : each.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition
                        && definition.getLeftOp() instanceof Local local) {
                    if (isRequiredAuthorities(each, definition.getRightOp())) {
                        requiredAuthorities.add(local);
                    }
                    if (definition.getRightOp() instanceof JNewExpr created
                            && !created.getType().getFullyQualifiedName().equals(DEFAULT_FACTORY)
                            && context.isApplication(created.getType())) {
                        graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The AuthorizationManagerFactory bean "
                                + MethodNames.key(method.getSignature()) + " is a custom " + created.getType()
                                .getFullyQualifiedName() + "; authorizeHttpRequests and pre/post rules are shown as the"
                                + " default factory builds them", MethodNames.codeRef(method.getSignature())));
                    }
                }
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty() || !invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName()
                        .equals(DEFAULT_FACTORY) || invoke.get().getArgCount() != 1) {
                    continue;
                }
                switch (invoke.get().getMethodSignature().getName()) {
                    case "setRolePrefix" -> {
                        if (invoke.get().getArg(0) instanceof StringConstant constant) {
                            prefix = constant.getValue();
                        }
                        else {
                            opaque(graph, method, "does not set its role prefix from a constant; role checks are shown"
                                    + " with ROLE_");
                        }
                    }
                    case "setRoleHierarchy" -> hierarchy = hierarchyArgument(context, graph, each, invoke.get(),
                            roleHierarchy, FACTORY_BEAN);
                    // Decision 0093 (AUTHZ-06): who counts as anonymous, remembered or fully authenticated.
                    case "setTrustResolver" -> opaque(graph, method, "decides who is anonymous, remembered or fully"
                            + " authenticated with its own AuthenticationTrustResolver; the authentication checks it"
                            + " builds are shown as Spring's default resolver decides them");
                    case "setAdditionalAuthorization" -> {
                        if (invoke.get().getArg(0) instanceof Local argument
                                && requiredAuthorities.contains(argument)) {
                            additional = MultiFactor.perUser(context);
                        }
                        else if (additional == null) {
                            opaque(graph, method, "adds an authorization to every rule it builds"
                                    + " (setAdditionalAuthorization); the graph does not show it, so those rules may"
                                    + " admit fewer callers than shown");
                        }
                    }
                    default -> {
                    }
                }
            }
        }
        return new Factory(prefix, hierarchy, additional);
    }

    /**
     * The application methods a setup method hands what it sets up to, or gets it from, one level down: a helper
     * that sets a factory's or a handler's role prefix or hierarchy sets them as the bean method would.
     *
     * @param setUp whether a type is what is set up
     */
    static List<JavaSootMethod> helpers(ScanContext context, JavaSootMethod method,
            java.util.function.Predicate<ClassType> setUp) {
        List<JavaSootMethod> found = new ArrayList<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty() || !context.isApplication(invoke.get().getMethodSignature().getDeclClassType())) {
                continue;
            }
            MethodSignature called = invoke.get().getMethodSignature();
            boolean handed = called.getParameterTypes().stream()
                    .anyMatch(type -> type instanceof ClassType given && setUp.test(given));
            boolean made = called.getType() instanceof ClassType returned && setUp.test(returned);
            if (handed || made) {
                context.findMethod(called).filter(JavaSootMethod::hasBody)
                        .filter(helper -> !helper.equals(method) && !found.contains(helper)).ifPresent(found::add);
            }
        }
        return found;
    }

    /**
     * AUTHZ-10: a {@code RequiredAuthoritiesAuthorizationManager}: a parameter, a bean method's result or a new one.
     */
    private static boolean isRequiredAuthorities(JavaSootMethod method, Value value) {
        if (value instanceof JParameterRef parameter) {
            return method.getParameterType(parameter.getIndex()) instanceof ClassType type
                    && type.getFullyQualifiedName().equals(MultiFactor.REQUIRED_AUTHORITIES);
        }
        if (value instanceof JNewExpr created) {
            return created.getType().getFullyQualifiedName().equals(MultiFactor.REQUIRED_AUTHORITIES);
        }
        return value instanceof AbstractInvokeExpr call && call.getMethodSignature().getType() instanceof ClassType type
                && type.getFullyQualifiedName().equals(MultiFactor.REQUIRED_AUTHORITIES);
    }

    /**
     * The hierarchy passed to {@code setRoleHierarchy}: the RoleHierarchy bean (a parameter, or a call to its bean
     * method), or one built in place.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    static RoleHierarchies hierarchyArgument(ScanContext context, GraphBuilder graph, JavaSootMethod method,
            AbstractInvokeExpr setter, RoleHierarchies roleHierarchy, String what) {
        if (setter.getArg(0) instanceof Local argument) {
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition && argument.equals(definition.getLeftOp())) {
                    if (definition.getRightOp() instanceof JParameterRef parameter
                            && method.getParameterType(parameter.getIndex()) instanceof ClassType type
                            && type.getFullyQualifiedName().equals(ROLE_HIERARCHY)) {
                        return roleHierarchy;
                    }
                    if (definition.getRightOp() instanceof AbstractInvokeExpr call
                            && call.getMethodSignature().getType() instanceof ClassType type
                            && type.getFullyQualifiedName().startsWith(ROLE_HIERARCHY)
                            && context.isApplication(call.getMethodSignature().getDeclClassType())) {
                        return roleHierarchy;
                    }
                }
            }
            Optional<RoleHierarchies> inline = RoleHierarchies.inline(method, argument);
            if (inline.isPresent()) {
                return inline.get();
            }
        }
        graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, what + MethodNames.key(method.getSignature())
                + " sets a RoleHierarchy that is not built from constants, so role checks may admit more roles than"
                + " the graph shows", MethodNames.codeRef(method.getSignature())));
        return RoleHierarchies.NONE;
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private static void opaque(GraphBuilder graph, JavaSootMethod method, String what) {
        graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, FACTORY_BEAN + MethodNames.key(method.getSignature())
                + " " + what, MethodNames.codeRef(method.getSignature())));
    }
}
