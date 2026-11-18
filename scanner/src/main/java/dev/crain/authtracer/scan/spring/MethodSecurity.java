package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.AuthorizationLocation.Scope;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.ClassFileMetadata;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.TypeProperties;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.MethodModifier;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.HasAnnotation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Method security ({@code @EnableMethodSecurity}): finds the annotations and decides whether each one is enforced.
 * Enforced annotations become Authorization Locations; the rest become {@link Finding.Kind#NOT_ENFORCED} findings.
 */
@Supports({Feature.METHOD_SECURITY, Feature.FIELD_CHECKS})
final class MethodSecurity {

    /**
     * The checks attached to one method, in the order Spring applies them.
     */
    record MethodChecks(List<AuthorizationLocation> pre, List<AuthorizationLocation> post) {
    }

    /**
     * SpEL in a Spring Data query: {@code ?#{..}} or {@code :#{..}}.
     */
    private static final Pattern QUERY_SPEL = Pattern.compile("[?:]#\\{([^}]*)}");
    private static final Pattern CALLER = Pattern.compile(
            "\\b(principal|authentication|hasRole|hasAuthority|hasAnyRole|hasAnyAuthority)\\b");
    private static final String SECURITY_EVALUATION_CONTEXT =
            "org.springframework.security.data.repository.query.SecurityEvaluationContextExtension";
    private static final String BOOT_SECURITY_AUTO_CONFIGURATION =
            "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration";
    private static final Set<String> PROXY_FACTORIES = Set.of(
            "org.springframework.security.authorization.AuthorizationProxyFactory",
            "org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory");
    private static final String TARGET_VISITOR =
            "org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory$TargetVisitor";
    private static final String TEMPLATE_DEFAULTS =
            "org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults";
    private static final String THROWING_HANDLER =
            "org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler";
    private static final String HINTS_REGISTRAR =
            "org.springframework.security.aot.hint.AuthorizeReturnObjectHintsRegistrar";
    private static final String PROXY_FACTORY = ProxyFactories.FACTORY;
    private static final String BUILT_FACTORY = ":built-factory";
    /**
     * 7.1.1 {@code MethodSecurityAspectJAutoProxyRegistrar}: the aspect each annotation's interceptor is handed to
     * under {@code @EnableMethodSecurity(mode = AdviceMode.ASPECTJ)}. JSR-250's annotations have none.
     */
    private static final Map<String, String> ASPECTS = Map.of(
            SpringNames.PRE_AUTHORIZE, "org.springframework.security.authorization.method.aspectj.PreAuthorizeAspect",
            SpringNames.POST_AUTHORIZE, "org.springframework.security.authorization.method.aspectj.PostAuthorizeAspect",
            SpringNames.PRE_FILTER, "org.springframework.security.authorization.method.aspectj.PreFilterAspect",
            SpringNames.POST_FILTER, "org.springframework.security.authorization.method.aspectj.PostFilterAspect",
            SpringNames.SECURED, "org.springframework.security.authorization.method.aspectj.SecuredAspect");
    /**
     * The legacy annotation's one aspect ({@code GlobalMethodSecurityAspectJAutoProxyRegistrar}): {@code @Secured}
     * and the pre/post annotations, not JSR-250's.
     */
    private static final String LEGACY_ASPECT =
            "org.springframework.security.access.intercept.aspectj.aspect.AnnotationSecurityAspect";
    private static final String ENABLE_LOAD_TIME_WEAVING =
            "org.springframework.context.annotation.EnableLoadTimeWeaving";
    private static final String CLOSURE = "$AjcClosure";
    private static final String AROUND_BODY = "_aroundBody";

    /**
     * @param offset {@code @EnableMethodSecurity(offset)}, added to each annotation interceptor's order
     * @param woven METHOD-14: {@code mode = AdviceMode.ASPECTJ}, so the checks are woven into the methods themselves
     *        rather than applied by a proxy
     */
    private record Config(boolean enabled, boolean prePost, boolean secured, boolean jsr250, int offset,
            boolean reactive, boolean woven, boolean legacy) {

        Config(boolean enabled, boolean prePost, boolean secured, boolean jsr250, int offset, boolean reactive,
                boolean woven) {
            this(enabled, prePost, secured, jsr250, offset, reactive, woven, false);
        }
    }


    private static final String TRANSACTIONAL = "org.springframework.transaction.annotation.Transactional";
    private static final String JAKARTA_TRANSACTIONAL = "jakarta.transaction.Transactional";
    private static final String ENABLE_TRANSACTIONS =
            "org.springframework.transaction.annotation.EnableTransactionManagement";

    private final ScanContext context;
    private final SpringBeans beans;
    private final GraphBuilder graph;
    private final SpelRequirements spel;
    private final StructureRules rules;
    private final SpelRequirements jsr250;
    private final Config config;
    /**
     * Decision 0111: what would enable method security if its class were surely a bean; {@code null} for nothing.
     */
    private String enabledOnlyWhen;
    private Boolean loadTimeWeaving;
    private final boolean templates;
    private final Set<String> returnObjectTypes = new HashSet<>();
    private final Map<String, MethodChecks> checks = new HashMap<>();
    private final MethodAdvisors advisors;
    private final CustomAdvisors customAdvisors;
    private final XmlMethodChecks xmlChecks;
    private final int transactionOrder;
    private final Set<String> withoutHierarchy = new HashSet<>();
    private final ProxyFactories proxyFactories;
    /**
     * The denial handler method of each check with an application's handler, by the check's id.
     */
    private final Map<String, Optional<JavaSootMethod>> handlers = new HashMap<>();
    /**
     * Decision 0088: the annotation checks of types only proxies hand out, by id, with the annotation and the check
     * as the default interceptors of a factory the application builds run it.
     */
    private final Map<String, Map.Entry<String, AuthorizationLocation>> builtFactory = new HashMap<>();
    /**
     * SpEL as Spring's default expression handler reads it: the {@code ROLE_} prefix.
     */
    private final SpelRequirements defaults;
    private final boolean jackson2;
    /**
     * EXPR-06: whether pre/post {@code hasPermission(..)} reaches a {@code PermissionEvaluator}.
     */
    private final boolean permissionEvaluator;
    /**
     * Decision 0091: what pre/post expressions read, and the method of each check whose expression names its
     * parameters, by the check's id.
     */
    private final ExpressionReads reads;
    private final Map<String, JavaSootMethod> withArguments = new LinkedHashMap<>();

    /**
     * @param prePostPrefix for pre/post SpEL: an {@code AuthorizationManagerFactory} bean's, else the
     *        {@code GrantedAuthorityDefaults} bean's
     * @param jsr250Prefix from a {@code GrantedAuthorityDefaults} bean; {@code @Secured} takes full authority names
     * @param xmlConfig the XML configuration: its {@code <method-security>} or {@code <global-method-security>}
     *        (decision 0036), and the method checks it sets up without annotations (decision 0097)
     */
    MethodSecurity(ScanContext context, SpringBeans beans, GraphBuilder graph, String prePostPrefix,
            String jsr250Prefix, SecurityXml.Config xmlConfig,
            Optional<ExpressionHandlers.Handler> handler, ProxyFactories proxyFactories) {
        Optional<SecurityXml.MethodSecurityConfig> xml = xmlConfig.methodSecurity();
        this.context = context;
        this.proxyFactories = proxyFactories;
        // The expression handler takes its default prefix (GrantedAuthorityDefaults', or its own when it is the
        // application's) off before the factory adds its; decision 0091: an application handler's root answers the
        // calls of its own methods.
        this.spel = new SpelRequirements(prePostPrefix, handler.map(ExpressionHandlers.Handler::strippedPrefix)
                .orElse(jsr250Prefix)).withBeans(DecisionCode.of(context))
                .withRoot(handler.map(ExpressionHandlers.Handler::root).orElse(null),
                        handler.map(ExpressionHandlers.Handler::rootIgnored).orElse(false));
        this.jsr250 = new SpelRequirements(jsr250Prefix);
        this.defaults = new SpelRequirements("ROLE_").withBeans(DecisionCode.of(context));
        this.beans = beans;
        this.graph = graph;
        this.reads = new ExpressionReads(context);
        this.jackson2 = TypeProperties.jackson2(context);
        Config annotated = readConfig();
        this.config = annotated.enabled() ? annotated : xml.map(found -> new Config(true, found.prePost(),
                found.secured(), found.jsr250(), 0, false, false)).orElse(annotated);
        this.permissionEvaluator = !config.prePost() || config.reactive()
                || PermissionEvaluators.configured(context, beans, xml, config.legacy());
        this.advisors = new MethodAdvisors(context, graph, config.enabled());
        this.customAdvisors = new CustomAdvisors(context, graph, beans, proxyFactory());
        this.xmlChecks = new XmlMethodChecks(context, graph, beans, xmlConfig, defaults);
        this.rules = new StructureRules(context, graph, defaults);
        this.transactionOrder = context.applicationClasses().stream()
                .flatMap(cls -> context.findAnnotation(cls, ENABLE_TRANSACTIONS).stream())
                .flatMap(enable -> Annotations.integer(enable, "order").stream())
                .findFirst().orElse(Integer.MAX_VALUE);
        this.templates = !SpringBeans.beanMethods(context, TEMPLATE_DEFAULTS).isEmpty();
        collectReturnObjectTypes();
        targetVisitors();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (cls.isAnnotation()) {
                continue;
            }
            for (JavaSootMethod method : cls.getMethods()) {
                // Kotlin copies a suspend function's annotations onto its static body, f$suspendImpl; Spring proxies f.
                if (!method.getName().startsWith("<") && !method.getName().endsWith("$suspendImpl")) {
                    detect(cls, method);
                }
            }
        }
    }

    /**
     * Decision 0014: the method's class is not a bean but a type an {@code @AuthorizeReturnObject} method returns, so
     * its checks run only on the authorization proxy that method hands out, whatever their scope.
     */
    boolean onlyOnReturnedProxy(JavaSootMethod method) {
        return returnObjectTypes.contains(method.getDeclaringClassType().getFullyQualifiedName())
                && !beans.isBean(method.getDeclaringClassType());
    }

    Optional<MethodChecks> checks(JavaSootMethod method) {
        return Optional.ofNullable(checks.get(MethodNames.key(method.getSignature())));
    }

    /**
     * Decision 0088: the check as it runs on an object a proxy factory the application built proxies. Such a factory
     * runs only the annotations it has interceptors for, as Spring's defaults read them (the {@code ROLE_} prefix, no
     * RoleHierarchy, no AuthorizationManagerFactory, no advisor bean's manager); the advisor beans' own checks not at
     * all. A check no proxy applies (a Provided one) runs anyway.
     */
    Optional<AuthorizationLocation> onBuiltProxy(AuthorizationLocation location, ProxyFactories.Factory factory) {
        if (!location.proxied()) {
            return Optional.of(location);
        }
        Map.Entry<String, AuthorizationLocation> built = builtFactory.get(location.id());
        if (built == null || !factory.applies(built.getKey())) {
            return Optional.empty();
        }
        AuthorizationLocation check = graph.node(built.getValue());
        withoutHierarchy.add(check.id());
        if (check.denial().kind() == Denial.Kind.HANDLER) {
            handlers.computeIfAbsent(check.id(), id -> handlerMethod(check.denial().handler(), check.phase()));
        }
        return Optional.of(check);
    }

    private boolean isTargetVisitor(sootup.core.types.Type type) {
        return type instanceof ClassType classType && classType.getFullyQualifiedName().equals(TARGET_VISITOR);
    }

    /**
     * EXPR-06: without a {@code PermissionEvaluator}, Spring's {@code DenyAllPermissionEvaluator} answers every
     * pre/post {@code hasPermission(..)}.
     */
    @Supports({Feature.FINDING_ALWAYS_DENIED, Feature.FINDING_ALWAYS_GRANTED})
    boolean permissionsDenied() {
        return !permissionEvaluator;
    }

    /**
     * Decision 0065: the class of the evaluator pre/post {@code hasPermission(..)} reaches, when AuthTracer can tell.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    Optional<ClassType> permissionEvaluator() {
        return permissionEvaluator && config.prePost() && !config.reactive()
                ? PermissionEvaluators.evaluator(context, beans, config.legacy()) : Optional.empty();
    }

    /**
     * Whether a RoleHierarchy widens this check: not for a manager built outside the annotation's own (AUTHZ-02,
     * METHOD-11), which is a static factory or custom code without one.
     */
    boolean hierarchyAware(AuthorizationLocation location) {
        return !withoutHierarchy.contains(location.id());
    }

    /**
     * FIELD-04: {@code proxyFactory.proxy(object)} returns an authorization proxy, like an
     * {@code @AuthorizeReturnObject} method.
     */
    static boolean isProxyCall(AbstractInvokeExpr invoke) {
        return invoke.getMethodSignature().getName().equals("proxy") && invoke.getArgCount() == 1
                && PROXY_FACTORIES.contains(invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName());
    }

    /**
     * Whether Spring wraps this method's result in an authorization proxy, which is what makes field-level
     * checks on the returned object run.
     */
    boolean returnsAuthorizedObject(JavaSootMethod method) {
        Optional<JavaSootClass> cls = context.findClass(method.getDeclaringClassType());
        return cls.isPresent() && beans.isBean(cls.get().getType()) && authorizesReturnObject(method);
    }

    /**
     * Whether the method's result is proxied when it is called through an authorization proxy: Spring's proxy of a
     * bean, or an object an {@code @AuthorizeReturnObject} method returned (a domain getter, which needs no bean).
     */
    boolean authorizesReturnObject(JavaSootMethod method) {
        return authorizesReturnObject(method, ProxyFactories.Factory.SPRING);
    }

    /**
     * Decision 0088 (amended): on a proxy a factory made, whether its {@code AuthorizeReturnObjectMethodInterceptor}
     * proxies the method's result: Spring Security's runs with any {@code @EnableMethodSecurity} (7.1.1's
     * {@code MethodSecuritySelector} imports {@code AuthorizationProxyConfiguration} whatever its flags say; with
     * {@code prePostEnabled = false} the proxy has no pre/post advisors, so the result's {@code @PreAuthorize} isn't
     * read either) and not with the legacy annotation; one the application builds runs its own, if it has one.
     */
    boolean authorizesReturnObject(JavaSootMethod method, ProxyFactories.Factory factory) {
        Optional<JavaSootClass> cls = context.findClass(method.getDeclaringClassType());
        return (factory.spring() ? springProxiesReturnedObjects()
                : factory.applies(SpringNames.AUTHORIZE_RETURN_OBJECT)) && cls.isPresent()
                && (context.hasAnnotation(method, SpringNames.AUTHORIZE_RETURN_OBJECT)
                        || context.hasAnnotation(cls.get(), SpringNames.AUTHORIZE_RETURN_OBJECT));
    }

    /**
     * A call to a method the application doesn't implement, e.g. {@code findById} inherited by a Spring Data
     * repository interface: proxied when the interface the call names is a bean with a class-level
     * {@code @AuthorizeReturnObject}.
     */
    boolean returnsAuthorizedObject(MethodSignature called) {
        Optional<JavaSootClass> cls = context.findClass(called.getDeclClassType());
        return springProxiesReturnedObjects() && cls.isPresent() && beans.isBean(cls.get().getType())
                && (context.hasAnnotation(cls.get(), SpringNames.AUTHORIZE_RETURN_OBJECT)
                        || context.findMethod(called).map(method -> context.hasAnnotation(method,
                                SpringNames.AUTHORIZE_RETURN_OBJECT)).orElse(false));
    }

    private boolean springProxiesReturnedObjects() {
        return config.enabled() && !config.legacy();
    }

    /**
     * Decision 0111: the first class that surely is a bean and carries the annotation; a class that may not be one
     * enables nothing, and is remembered for the NOT_ENFORCED findings (the weaker reading).
     */
    private Optional<AnnotationUsage> enabling(String annotationName) {
        for (JavaSootClass cls : context.applicationClasses()) {
            Optional<AnnotationUsage> enable = context.findAnnotation(cls, annotationName);
            if (enable.isEmpty()) {
                continue;
            }
            Optional<String> maybe = BeanConditions.of(context).maybe(cls);
            if (maybe.isEmpty()) {
                return enable;
            }
            if (enabledOnlyWhen == null) {
                enabledOnlyWhen = "@" + annotationName.substring(annotationName.lastIndexOf('.') + 1) + " on "
                        + cls.getName() + ", which is only a bean when " + maybe.get();
            }
        }
        return Optional.empty();
    }

    private Config readConfig() {
        Optional<AnnotationUsage> enable = enabling(SpringNames.ENABLE_METHOD_SECURITY);
        if (enable.isPresent()) {
            return new Config(true,
                    Annotations.bool(enable.get(), "prePostEnabled").orElse(true),
                    Annotations.bool(enable.get(), "securedEnabled").orElse(false),
                    Annotations.bool(enable.get(), "jsr250Enabled").orElse(false),
                    Annotations.integer(enable.get(), "offset").orElse(0), false,
                    Annotations.string(enable.get(), "mode").filter("ASPECTJ"::equals).isPresent());
        }
        // METHOD-16: the legacy annotation, through the Access API; everything is off unless enabled.
        Optional<AnnotationUsage> legacy = enabling(SpringNames.ENABLE_GLOBAL_METHOD_SECURITY);
        if (legacy.isPresent()) {
            return new Config(true,
                    Annotations.bool(legacy.get(), "prePostEnabled").orElse(false),
                    Annotations.bool(legacy.get(), "securedEnabled").orElse(false),
                    Annotations.bool(legacy.get(), "jsr250Enabled").orElse(false), 0, false,
                    Annotations.string(legacy.get(), "mode").filter("ASPECTJ"::equals).isPresent(), true);
        }
        // RX-05: reactive method security has pre/post only (7.1.1 ReactiveAuthorizationManagerMethodSecurityConfiguration).
        if (enabling(SpringNames.ENABLE_REACTIVE_METHOD_SECURITY).isPresent()) {
            return new Config(true, true, false, false, 0, true, false);
        }
        return new Config(false, false, false, false, 0, false, false);
    }

    /**
     * Types whose instances Spring wraps in an authorization proxy because an {@code @AuthorizeReturnObject} method
     * returns them (directly, or as the element type of a collection or optional).
     */
    private void collectReturnObjectTypes() {
        for (JavaSootClass cls : context.applicationClasses()) {
            boolean classLevel = context.hasAnnotation(cls, SpringNames.AUTHORIZE_RETURN_OBJECT);
            for (JavaSootMethod method : cls.getMethods()) {
                if (!classLevel && !context.hasAnnotation(method, SpringNames.AUTHORIZE_RETURN_OBJECT)) {
                    continue;
                }
                if (method.getReturnType() instanceof ClassType returned && context.isApplication(returned)) {
                    returnObjectTypes.add(returned.getFullyQualifiedName());
                }
                returnObjectTypes.addAll(context.classFiles().returnTypeArguments(method.getSignature()).stream()
                        .filter(name -> context.isApplication(context.type(name)))
                        .toList());
            }
        }
        collectProxiedTypes();
        hintedTypes();
    }

    /**
     * FIELD-07: {@code new AuthorizeReturnObjectHintsRegistrar(proxyFactory, Account.class, ..)} (or a list of
     * classes) names the types the application's proxies hold where erased generics hide them.
     */
    private void hintedTypes() {
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt).filter(call -> call.getMethodSignature()
                            .getName().equals("<init>") && call.getMethodSignature().getDeclClassType()
                                    .getFullyQualifiedName().equals(HINTS_REGISTRAR));
                    if (invoke.isEmpty() || invoke.get().getArgCount() != 2
                            || !(invoke.get().getArg(1) instanceof Local classes)) {
                        continue;
                    }
                    // An array of class constants, or List.of(..) of them.
                    List<Value> named = new ArrayList<>(Locals.elements(method.getBody(), classes));
                    Locals.definition(method.getBody(), classes).filter(AbstractInvokeExpr.class::isInstance)
                            .map(AbstractInvokeExpr.class::cast).ifPresent(list -> list.getArgs().forEach(arg ->
                                    named.addAll(arg instanceof Local array ? Locals.elements(method.getBody(), array)
                                            : List.of(arg))));
                    named.stream().map(GroovyCalls::className).flatMap(Optional::stream)
                            .filter(name -> context.isApplication(context.type(name))).forEach(returnObjectTypes::add);
                }
            }
        }
    }

    /**
     * The types of objects passed to {@code AuthorizationProxyFactory#proxy}: the argument's static type, or for a
     * collection, optional or stream (which the factory proxies per element) the element type, read from the
     * generic return type of the call that produced it.
     */
    @Might("Read element types from generic parameters, fields and local variable tables too")
    private void collectProxiedTypes() {
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    if (!stmt.isInvokableStmt()) {
                        continue;
                    }
                    stmt.asInvokableStmt().getInvokeExpr().filter(MethodSecurity::isProxyCall).ifPresent(invoke -> {
                        if (invoke.getArg(0).getType() instanceof ClassType type && context.isApplication(type)) {
                            returnObjectTypes.add(type.getFullyQualifiedName());
                        }
                        else if (invoke.getArg(0) instanceof Local local) {
                            elementTypes(method, local, 2).forEach(returnObjectTypes::add);
                        }
                    });
                }
            }
        }
    }

    /**
     * Application types among the type arguments of whatever call defines the local, following casts.
     */
    private List<String> elementTypes(JavaSootMethod method, Local local, int depth) {
        List<String> types = new ArrayList<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (depth > 0 && stmt instanceof AbstractDefinitionStmt definition && local.equals(definition.getLeftOp())) {
                if (definition.getRightOp() instanceof AbstractInvokeExpr call) {
                    context.classFiles().returnTypeArguments(call.getMethodSignature()).stream()
                            .filter(name -> context.isApplication(context.type(name))).forEach(types::add);
                }
                else if (definition.getRightOp() instanceof JCastExpr cast && cast.getOp() instanceof Local other) {
                    types.addAll(elementTypes(method, other, depth - 1));
                }
                else if (definition.getRightOp() instanceof Local other) {
                    types.addAll(elementTypes(method, other, depth - 1));
                }
            }
        }
        return types;
    }

    /**
     * FIELD-03: a {@code TargetVisitor} decides which returned objects get proxied. Spring's
     * {@code defaultsSkipValueTypes()} only skips values like {@code String} (no field checks there); any other
     * visitor may hand an object back unproxied, and then its field checks don't run.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void targetVisitors() {
        if (returnObjectTypes.isEmpty()) {
            return;
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                boolean visitorBean = context.hasAnnotation(method, SpringNames.BEAN)
                        && method.getReturnType() instanceof ClassType returned
                        && returned.getFullyQualifiedName().equals(TARGET_VISITOR);
                boolean setsVisitor = method.getBody().getStmts().stream()
                        .flatMap(stmt -> Locals.invoke(stmt).stream())
                        .anyMatch(invoke -> invoke.getMethodSignature().getName().equals("setTargetVisitor"));
                boolean custom = method.getBody().getStmts().stream()
                        .filter(stmt -> stmt instanceof AbstractDefinitionStmt).map(stmt -> ((AbstractDefinitionStmt) stmt)
                                .getRightOp())
                        .anyMatch(right -> right instanceof JDynamicInvokeExpr dynamic && isTargetVisitor(dynamic.getType())
                                || right instanceof JNewExpr created && context.interfacesOf(created.getType()).stream()
                                        .anyMatch(this::isTargetVisitor)
                                || right instanceof AbstractInvokeExpr call && context.isApplication(call
                                        .getMethodSignature().getDeclClassType()) && isTargetVisitor(call
                                                .getMethodSignature().getType()));
                if ((visitorBean || setsVisitor) && custom) {
                    graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, MethodNames.key(method.getSignature())
                            + " sets a custom TargetVisitor, which decides which returned objects become authorization"
                            + " proxies; field checks on the objects it skips don't run",
                            MethodNames.codeRef(method.getSignature())));
                }
                proxyAdvisors(method);
            }
        }
    }

    /**
     * FIELD-06: a {@code Customizer<AuthorizationAdvisorProxyFactory>} (or any code) that changes the advisors the
     * proxy factory applies: {@code setAdvisors(..)} replaces the annotations' interceptors, so the checks on the
     * objects it proxies may not run; {@code addAdvisor(..)} adds one AuthTracer doesn't read.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void proxyAdvisors(JavaSootMethod method) {
        Set<String> calls = new HashSet<>();
        method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                        .equals(PROXY_FACTORY))
                .forEach(invoke -> calls.add(invoke.getMethodSignature().getName()));
        String key = MethodNames.key(method.getSignature());
        if (calls.contains("setAdvisors")) {
            ProxyFactories.Factory spring = proxyFactories.spring();
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, key + " replaces the advisors"
                    + " AuthorizationProxyFactory applies to the objects it proxies (@AuthorizeReturnObject)"
                    + (proxyFactories.customizes(method) && spring.customized()
                            ? ": they show the checks of the Spring interceptors it sets, " + spring.describe()
                                    + "; no other advisor's"
                            : ": the checks shown on them, field checks among them, may not run"),
                    MethodNames.codeRef(method.getSignature())));
        }
        if (calls.contains("addAdvisor")) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, key + " adds an advisor to those"
                    + " AuthorizationProxyFactory applies to the objects it proxies (@AuthorizeReturnObject);"
                    + " AuthTracer doesn't read what it decides", MethodNames.codeRef(method.getSignature())));
        }
    }

    /**
     * FIELD-08: a Spring Data {@code @Query} whose SpEL reads the caller ({@code ?#{principal.id}},
     * {@code :#{authentication.name}}) returns only the caller's rows: a filter on the repository method, with that
     * expression. Without a {@code SecurityEvaluationContextExtension} bean the query can't evaluate it and fails.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void queryFilter(JavaSootClass cls, JavaSootMethod method,
            List<Map.Entry<Integer, AuthorizationLocation>> post) {
        Optional<String> query = Optional.empty();
        for (AnnotationUsage annotation : method.getAnnotations()) {
            String name = Annotations.name(annotation);
            if (name.startsWith("org.springframework.data.") && name.endsWith(".Query")) {
                query = Annotations.string(annotation, "value");
            }
        }
        if (query.isEmpty()) {
            return;
        }
        List<String> callers = new ArrayList<>();
        Matcher spel = QUERY_SPEL.matcher(query.get());
        while (spel.find()) {
            String expression = spel.group(1).trim();
            if (CALLER.matcher(expression).find()) {
                callers.add(expression);
            }
        }
        if (callers.isEmpty()) {
            return;
        }
        String key = MethodNames.key(method.getSignature());
        if (!securityEvaluationContext()) {
            graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "The @Query of " + key + " reads the caller ("
                    + String.join(", ", callers) + ") but there is no SecurityEvaluationContextExtension bean, so the"
                    + " query can't evaluate it", MethodNames.codeRef(method.getSignature())));
        }
        AuthorizationLocation location = graph.node(new AuthorizationLocation("location:METHOD:" + key + ":@Query",
                "@Query", Scope.METHOD, Phase.POST, Requirement.expression("query rows filtered by "
                        + String.join(" and ", callers)), MethodNames.codeRef(method.getSignature()), null, null,
                new Denial(Denial.Kind.FILTER, null), true));
        post.add(Map.entry(Integer.MAX_VALUE, location));
    }

    private Boolean securityEvaluationContext;

    private boolean securityEvaluationContext() {
        if (securityEvaluationContext == null) {
            // The application's own bean, or Spring Boot's (4.1.1 SecurityAutoConfiguration.SecurityDataConfiguration,
            // when spring-security-data is on the classpath).
            boolean bootDefines = context.findClass(SECURITY_EVALUATION_CONTEXT).isPresent()
                    && context.findClass(BOOT_SECURITY_AUTO_CONFIGURATION).isPresent()
                    && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION);
            securityEvaluationContext = bootDefines
                    || !SpringBeans.beanMethods(context, SECURITY_EVALUATION_CONTEXT).isEmpty();
        }
        return securityEvaluationContext;
    }

    @Supports(Feature.FINDING_NOT_ENFORCED)
    private void detect(JavaSootClass cls, JavaSootMethod method) {
        List<Map.Entry<Integer, AuthorizationLocation>> pre = new ArrayList<>();
        List<Map.Entry<Integer, AuthorizationLocation>> post = new ArrayList<>();
        // 7.1.1 Jsr250AuthorizationManager: @DenyAll, @PermitAll and @RolesAllowed are looked up as one, the closest.
        Optional<Map.Entry<String, AnnotationUsage>> jsr250 = find(cls, method, SpringNames.JSR_250);
        for (String annotationName : SpringNames.METHOD_SECURITY) {
            Optional<AnnotationUsage> annotation = SpringNames.JSR_250.contains(annotationName)
                    ? jsr250.filter(found -> found.getKey().equals(annotationName)).map(Map.Entry::getValue)
                    : find(cls, method, List.of(annotationName)).map(Map.Entry::getValue);
            if (annotation.isEmpty()) {
                continue;
            }
            String simpleName = "@" + MethodNames.simpleName(annotationName);
            Optional<String> notEnforced = notEnforcedReason(cls, method, annotationName, simpleName);
            if (notEnforced.isPresent()) {
                graph.finding(new Finding(Finding.Kind.NOT_ENFORCED, notEnforced.get(),
                        MethodNames.codeRef(method.getSignature())));
                continue;
            }
            boolean field = returnObjectTypes.contains(cls.getName()) && !beans.isBean(cls.getType())
                    && getterField(method).isPresent();
            Scope scope = field ? Scope.FIELD : Scope.METHOD;
            Phase phase = annotationName.equals(SpringNames.POST_AUTHORIZE)
                    || annotationName.equals(SpringNames.POST_FILTER) ? Phase.POST : Phase.PRE;
            String id = "location:" + scope + ":" + MethodNames.key(method.getSignature()) + ":" + simpleName;
            // A manager that is its own denied handler (an advisor's) comes before @HandleAuthorizationDenied.
            Optional<Denial> advisorDenial = advisorsFor(annotationName).stream()
                    .map(MethodAdvisors.AnnotationAdvisor::handler).filter(Objects::nonNull).findFirst()
                    .map(handler -> new Denial(Denial.Kind.HANDLER, handler));
            Denial denial = advisorDenial.orElseGet(() -> denial(cls, method, annotationName));
            if (advisorDenial.isEmpty()) {
                unregisteredHandler(method, simpleName, denial);
            }
            if (denial.kind() == Denial.Kind.HANDLER) {
                handlers.put(id, handlerMethod(denial.handler(), phase));
            }
            AuthorizationLocation location = graph.node(read(method, annotationName, annotation.get(),
                    new AuthorizationLocation(id, simpleName, scope, phase, withAdvisors(annotationName,
                            requirement(annotationName, annotation.get(), spel, this.jsr250), id),
                            MethodNames.codeRef(method.getSignature()), field ? getterField(method).get() : null,
                            null, denial, !woven(cls, method, annotationName))));
            if (onlyOnReturnedProxy(method)) {
                // Decision 0088: as Spring's default interceptor reads it, for a factory the application builds.
                builtFactory.put(id, Map.entry(annotationName, new AuthorizationLocation(id + BUILT_FACTORY,
                        simpleName, scope, phase, requirement(annotationName, annotation.get(), defaults,
                                defaults), location.target(), location.field(), null,
                        denial(cls, method, annotationName), location.proxied())
                        .withReads(location.arguments(), location.claims())));
                if (location.arguments() != null) {
                    withArguments.put(id + BUILT_FACTORY, method);
                }
            }
            (phase == Phase.PRE ? pre : post).add(Map.entry(order(annotationName), location));
        }
        // Decision 0097: what the XML namespace checks without annotations; its managers have no RoleHierarchy.
        boolean annotated = !pre.isEmpty() || !post.isEmpty();
        for (XmlMethodChecks.Check check : xmlChecks.checks(cls, method, annotated)) {
            withoutHierarchy.add(check.location().id());
            pre.add(Map.entry(check.order(), check.location()));
        }
        queryFilter(cls, method, post);
        pointcutChecks(cls, method, pre, post);
        afterCommit(cls, method, post);
        // Interceptors nest by order: the lowest runs first on the way in and last on the way out.
        List<AuthorizationLocation> before = new ArrayList<>(pre.stream()
                .sorted(Map.Entry.comparingByKey()).map(Map.Entry::getValue).toList());
        List<AuthorizationLocation> after = post.stream()
                .sorted(Map.Entry.<Integer, AuthorizationLocation>comparingByKey().reversed())
                .map(Map.Entry::getValue).toList();
        providedCheck(method).ifPresent(before::add);
        // Decision 0120: an authorization library's annotation, as a rule describes it, applied by its aspect's proxy
        // (Spring Security's AspectJ mode doesn't weave the library's aspect).
        for (String annotationName : rules.annotations()) {
            find(cls, method, List.of(annotationName)).ifPresent(found -> before.add(rules.annotated(method,
                    annotationName, found.getValue())));
        }
        if (!before.isEmpty() || !after.isEmpty()) {
            checks.put(MethodNames.key(method.getSignature()), new MethodChecks(before, after));
        }
    }

    /**
     * Whether Spring Security's {@code AuthorizationProxyFactory} bean exists: 7.1.1's {@code @EnableMethodSecurity}
     * imports {@code AuthorizationProxyConfiguration}; the legacy and the reactive annotations don't.
     */
    private boolean proxyFactory() {
        return config.enabled() && !config.legacy() && !config.reactive();
    }

    private boolean flagEnabled(String annotationName) {
        return config.enabled() && (SpringNames.PRE_POST.contains(annotationName) ? config.prePost()
                : annotationName.equals(SpringNames.SECURED) ? config.secured() : config.jsr250());
    }

    /**
     * Where the annotation's check runs among the method's interceptors: Spring Security's own interceptor's order
     * (plus {@code @EnableMethodSecurity(offset)}) when its flag is on, and decision 0092: an advisor bean's for it,
     * as {@code setOrder(..)} leaves it; the first of them when there are several.
     */
    private int order(String annotationName) {
        int own = MethodAdvisors.ORDERS.get(annotationName);
        List<MethodAdvisors.AnnotationAdvisor> advisorBeans = advisorsFor(annotationName);
        if (advisorBeans.isEmpty()) {
            return own + (flagEnabled(annotationName) ? config.offset() : 0);
        }
        int order = flagEnabled(annotationName) ? own + config.offset() : Integer.MAX_VALUE;
        for (MethodAdvisors.AnnotationAdvisor advisor : advisorBeans) {
            order = Math.min(order, advisor.order());
        }
        return order;
    }

    private List<MethodAdvisors.AnnotationAdvisor> advisorsFor(String annotationName) {
        return advisors.annotations().stream().filter(advisor -> advisor.annotation().equals(annotationName)
                || advisor.annotation().equals(SpringNames.ROLES_ALLOWED) && SpringNames.JSR_250.contains(
                        annotationName)).toList();
    }

    /**
     * METHOD-12, AUTHZ-02: each interceptor that handles the annotation must pass. One built from the annotation's
     * own manager adds nothing new; one with a custom manager adds that manager's requirement.
     */
    private Requirement withAdvisors(String annotationName, Requirement own, String id) {
        List<Requirement> all = new ArrayList<>();
        if (flagEnabled(annotationName)) {
            all.add(own);
        }
        for (MethodAdvisors.AnnotationAdvisor advisor : advisorsFor(annotationName)) {
            Requirement next = advisor.custom() == null ? own : advisor.custom();
            if (!all.contains(next)) {
                all.add(next);
            }
        }
        // Empty only for a factory the application builds (notEnforcedReason), which onBuiltProxy reads.
        // Decision 0092: a custom manager given the RoleHierarchy is widened by it; when one of several is, all are,
        // the weaker reading.
        if (!all.contains(own) && advisorsFor(annotationName).stream().noneMatch(
                MethodAdvisors.AnnotationAdvisor::hierarchy)) {
            withoutHierarchy.add(id);
        }
        return all.isEmpty() ? own : all.size() == 1 ? all.getFirst() : Requirement.and(all);
    }

    /**
     * METHOD-11: pointcut advisors guard the bean methods their pointcut matches, through the same proxy.
     */
    private void pointcutChecks(JavaSootClass cls, JavaSootMethod method,
            List<Map.Entry<Integer, AuthorizationLocation>> pre, List<Map.Entry<Integer, AuthorizationLocation>> post) {
        boolean bean = beans.isBean(cls.getType());
        // FIELD-06 (decision 0077): the proxy factory bean (servlet method security's) applies every
        // AuthorizationAdvisor bean to the objects it proxies.
        boolean returned = !bean && proxyFactory() && returnObjectTypes.contains(cls.getName());
        if (!bean && !returned || cls.isInterface() || method.isPrivate() || method.isFinal() || method.isStatic()) {
            return;
        }
        Optional<String> field = returned ? getterField(method) : Optional.empty();
        Scope scope = field.isPresent() ? Scope.FIELD : Scope.METHOD;
        for (PointcutGuard advisor : pointcutGuards()) {
            if (!(bean ? advisor.beans() : advisor.proxies()) || !advisor.pointcut().matches(cls, method)) {
                continue;
            }
            String id = "location:" + scope + ":" + MethodNames.key(method.getSignature()) + ":advisor:"
                    + advisor.key();
            if (!advisor.hierarchy()) {
                withoutHierarchy.add(id);
            }
            AuthorizationLocation location = graph.node(new AuthorizationLocation(id, "Advisor " + advisor.name(),
                    scope, advisor.phase(), advisor.requirement(), MethodNames.codeRef(method.getSignature()),
                    field.orElse(null), advisor.expression(), advisor.handler() == null ? Denial.THROW
                            : new Denial(Denial.Kind.HANDLER, advisor.handler()), true));
            (advisor.phase() == Phase.PRE ? pre : post).add(Map.entry(advisor.order(), location));
        }
    }

    /**
     * An advisor that guards the methods its pointcut matches: an interceptor bean's (METHOD-11), on beans and on
     * returned proxies, or an application's own {@code AuthorizationAdvisor} (FIELD-06), whose advice isn't read.
     *
     * @param key what tells it apart in a Location's id
     */
    /**
     * @param hierarchy its manager is given the RoleHierarchy (decision 0092)
     */
    private record PointcutGuard(Pointcuts.Pointcut pointcut, String expression, Requirement requirement,
            Phase phase, int order, String name, String key, boolean beans, boolean proxies, String handler,
            boolean hierarchy) {
    }

    private List<PointcutGuard> pointcutGuards;

    private List<PointcutGuard> pointcutGuards() {
        if (pointcutGuards == null) {
            pointcutGuards = new ArrayList<>();
            for (MethodAdvisors.PointcutAdvisor advisor : advisors.pointcutAdvisors()) {
                pointcutGuards.add(new PointcutGuard(advisor.pointcut(), advisor.expression(), advisor.requirement(),
                        advisor.phase(), advisor.order(), advisor.bean().getName() + "()",
                        MethodNames.key(advisor.bean().getSignature()), true, true, advisor.handler(),
                        advisor.hierarchy()));
            }
            for (CustomAdvisors.Advisor advisor : customAdvisors.advisors()) {
                String name = MethodNames.simpleName(advisor.type().getName());
                pointcutGuards.add(new PointcutGuard(advisor.pointcut(), advisor.expression(),
                        Requirement.expression("custom AuthorizationAdvisor " + name), Phase.PRE, advisor.order(),
                        name, advisor.type().getName(), advisor.beans(), advisor.proxies(), null, false));
            }
        }
        return pointcutGuards;
    }

    /**
     * METHOD-13: method security wraps the transaction unless its order comes after the transaction advice's
     * ({@code LOWEST_PRECEDENCE} unless {@code @EnableTransactionManagement(order)} says otherwise), so a post check on
     * a {@code @Transactional} method decides after the commit.
     */
    @Supports(Feature.FINDING_CHECK_AFTER_COMMIT)
    private void afterCommit(JavaSootClass cls, JavaSootMethod method,
            List<Map.Entry<Integer, AuthorizationLocation>> post) {
        Optional<AnnotationUsage> transactional = context.findAnnotation(method, TRANSACTIONAL)
                .or(() -> context.findAnnotation(cls, TRANSACTIONAL));
        boolean writes = transactional.isPresent()
                ? !Annotations.bool(transactional.get(), "readOnly").orElse(false)
                : context.hasAnnotation(method, JAKARTA_TRANSACTIONAL) || context.hasAnnotation(cls, JAKARTA_TRANSACTIONAL);
        if (!writes || !beans.isBean(cls.getType())) {
            return;
        }
        for (Map.Entry<Integer, AuthorizationLocation> check : post) {
            if (check.getKey() < transactionOrder) {
                graph.finding(new Finding(Finding.Kind.CHECK_AFTER_COMMIT, check.getValue().mechanism() + " on "
                        + MethodNames.key(method.getSignature()) + " runs outside its @Transactional boundary"
                        + " (interceptor order " + check.getKey() + ", transactions " + (transactionOrder
                                == Integer.MAX_VALUE ? "LOWEST_PRECEDENCE" : transactionOrder) + "), so it decides"
                        + " after the commit: a denied caller gets an error, but what the method wrote is saved",
                        MethodNames.codeRef(method.getSignature())));
            }
        }
    }

    /**
     * A reviewed hand-rolled check, declared as a Provided fact, runs inside the method body (no proxy involved).
     */
    @Supports(Feature.PROVIDED_FACTS)
    private Optional<AuthorizationLocation> providedCheck(JavaSootMethod method) {
        String key = MethodNames.key(method.getSignature());
        return context.input().facts().about(ProvidedFact.Kind.CHECK, key).map(fact -> graph.node(
                new AuthorizationLocation("location:METHOD:" + key + ":provided", "Provided check (" + fact.origin()
                        + ")", Scope.METHOD, Phase.PRE, fact.requirement() == null
                                // What it asks for wasn't given: shown as that, not guessed.
                                ? Requirement.expression("a reviewed check whose requirement wasn't given")
                                : spel.parse(fact.requirement()), MethodNames.codeRef(method.getSignature()), null,
                        null, Denial.THROW, false)));
    }

    @Supports(Feature.FINDING_NOT_ENFORCED)
    private Optional<String> notEnforcedReason(JavaSootClass cls, JavaSootMethod method, String annotationName,
            String simpleName) {
        String where = cls.getName() + "#" + method.getName();
        // Decision 0088 (amended): a factory the application builds runs its interceptors on the objects it proxies,
        // with method security or without.
        boolean advised = !advisorsFor(annotationName).isEmpty()
                || onlyOnReturnedProxy(method) && proxyFactories.builds(annotationName);
        if (!config.enabled() && !advised) {
            return Optional.of(simpleName + " on " + where + (enabledOnlyWhen != null ? " may never run: method"
                    + " security is enabled only by " + enabledOnlyWhen + ", which AuthTracer can't decide"
                    : " never runs: method security is not enabled (no @EnableMethodSecurity)"));
        }
        if (SpringNames.PRE_POST.contains(annotationName) && !config.prePost() && !advised) {
            return Optional.of(simpleName + " on " + where + " never runs: prePostEnabled = false");
        }
        if (config.reactive() && !SpringNames.PRE_POST.contains(annotationName) && !advised) {
            return Optional.of(simpleName + " on " + where + " never runs: @EnableReactiveMethodSecurity only handles"
                    + " @PreAuthorize, @PostAuthorize, @PreFilter and @PostFilter");
        }
        if (annotationName.equals(SpringNames.SECURED) && !config.secured() && !advised) {
            return Optional.of(simpleName + " on " + where + " never runs: needs"
                    + " @EnableMethodSecurity(securedEnabled = true)");
        }
        if (SpringNames.JSR_250.contains(annotationName) && !config.jsr250() && !advised) {
            return Optional.of(simpleName + " on " + where + " never runs: needs"
                    + " @EnableMethodSecurity(jsr250Enabled = true)");
        }
        if (woven(cls, method, annotationName)) {
            // AspectJ weaves the check into the method: any object, any method, calls on this included.
            return Optional.empty();
        }
        if (config.woven() && !advised) {
            // 7.1.1: only MethodSecurityAdvisorRegistrar, which PROXY mode alone imports, makes the interceptors
            // advisors, so no proxy applies them either.
            return Optional.of(simpleName + " on " + where + (aspect(annotationName).isEmpty()
                    ? " never runs: mode = AdviceMode.ASPECTJ has no aspect for it, and makes no advisor of it"
                    : " may never run: mode = AdviceMode.ASPECTJ leaves it to AspectJ, and " + cls.getName()
                            + " isn't woven at compile time (an AspectJ load-time weaving agent may weave it)"));
        }
        if (!beans.isProxied(cls.getType()) && !returnObjectTypes.contains(cls.getName())) {
            return Optional.of(simpleName + " on " + where + " never runs: " + cls.getName()
                    + " is not a Spring bean and is not returned from an @AuthorizeReturnObject method");
        }
        if (method.isPrivate() || method.isFinal() || method.isStatic()) {
            return Optional.of(simpleName + " on " + where + " never runs: Spring's proxy can't intercept "
                    + (method.isPrivate() ? "private" : method.isFinal() ? "final" : "static") + " methods");
        }
        return Optional.empty();
    }

    /**
     * METHOD-14: whether AspectJ weaves the annotation's check into the method, so that it runs on any call. Under
     * {@code mode = AdviceMode.ASPECTJ} Spring Security hands the annotation's interceptor to an aspect, which runs
     * only where it is woven: at compile time (ajc's woven method, or an around body its closures run, calls the
     * aspect's {@code aspectOf()}), or as classes load, with {@code @EnableLoadTimeWeaving} on a class that surely
     * is a bean (an application with it doesn't start without a weaver).
     */
    private boolean woven(JavaSootClass cls, JavaSootMethod method, String annotationName) {
        Optional<String> aspect = aspect(annotationName);
        return config.woven() && aspect.isPresent() && (loadTimeWeaving() && context.findClass(aspect.get())
                .isPresent() || callsAspect(cls, method, aspect.get(), new HashSet<>()));
    }

    private Optional<String> aspect(String annotationName) {
        return config.legacy() ? Optional.of(LEGACY_ASPECT).filter(legacy -> !SpringNames.JSR_250
                .contains(annotationName)) : Optional.ofNullable(ASPECTS.get(annotationName));
    }

    private boolean loadTimeWeaving() {
        if (loadTimeWeaving == null) {
            loadTimeWeaving = context.applicationClasses().stream().anyMatch(cls -> context.findAnnotation(cls,
                    ENABLE_LOAD_TIME_WEAVING).filter(enable -> Annotations.string(enable, "aspectjWeaving")
                            .filter("DISABLED"::equals).isEmpty()).isPresent()
                    && BeanConditions.of(context).maybe(cls).isEmpty());
        }
        return loadTimeWeaving;
    }

    /**
     * Whether the method, or the around bodies ajc moved its code to, calls the aspect's {@code aspectOf()}: the
     * closure a woven method makes ({@code Owner$AjcClosureN}) runs the next body ({@code name_aroundBodyN}).
     */
    private boolean callsAspect(JavaSootClass cls, JavaSootMethod method, String aspect, Set<String> seen) {
        if (!method.hasBody() || !seen.add(method.getSignature().toString())) {
            return false;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals("aspectOf")
                    && invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName().equals(aspect)) {
                return true;
            }
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getRightOp() instanceof JNewExpr created
                    && created.getType().getFullyQualifiedName().startsWith(cls.getName() + CLOSURE)) {
                Optional<JavaSootMethod> next = context.findClass(created.getType()).stream()
                        .flatMap(closure -> closure.getMethods().stream())
                        .filter(run -> run.getName().equals("run") && run.hasBody())
                        .flatMap(run -> run.getBody().getStmts().stream())
                        .flatMap(runStmt -> Locals.invoke(runStmt).stream())
                        .map(AbstractInvokeExpr::getMethodSignature)
                        .filter(body -> body.getName().contains(AROUND_BODY)
                                && body.getDeclClassType().equals(cls.getType()))
                        .findFirst().flatMap(context::findMethod);
                if (next.isPresent() && callsAspect(cls, next.get(), aspect, seen)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Spring Security 7.1.1's lookup ({@code UniqueSecurityAnnotationScanner#findMethodAnnotations}): the method, then
     * the methods it overrides, up the superclasses and then the interfaces; only then the class, its superclasses
     * and its interfaces. The closest of the annotations wins. The class's pointcut ({@code AuthorizationMethodPointcuts},
     * an {@code AnnotationMatchingPointcut} on the class) matches every method, so a package-private or protected
     * handler gets the class's annotation too (its CGLIB proxy intercepts it); a private or static one is never
     * called through the proxy.
     */
    private Optional<Map.Entry<String, AnnotationUsage>> find(JavaSootClass cls, JavaSootMethod method,
            List<String> annotationNames) {
        Optional<Map.Entry<String, AnnotationUsage>> found = closestMethod(cls.getType(), method, annotationNames,
                new HashSet<>());
        return found.isPresent() || method.isPrivate() || method.isStatic() ? found
                : closestClass(cls.getType(), annotationNames, new HashSet<>());
    }

    private Optional<Map.Entry<String, AnnotationUsage>> closestMethod(ClassType type, JavaSootMethod method,
            List<String> annotationNames, Set<String> seen) {
        Optional<JavaSootClass> cls = seen.add(type.getFullyQualifiedName()) ? context.findClass(type)
                : Optional.empty();
        if (cls.isEmpty()) {
            return Optional.empty();
        }
        Optional<JavaSootMethod> declared = cls.get().getMethod(method.getSubSignature())
                .or(() -> cls.get().getMethods().stream().filter(candidate -> overrides(context, candidate, method))
                        .findFirst());
        Optional<Map.Entry<String, AnnotationUsage>> found = declared.flatMap(candidate -> lookup(candidate,
                annotationNames));
        if (found.isPresent()) {
            return found;
        }
        List<ClassType> above = new ArrayList<>();
        cls.get().getSuperclass().ifPresent(above::add);
        above.addAll(cls.get().getInterfaces());
        for (ClassType supertype : above) {
            found = closestMethod(supertype, method, annotationNames, seen);
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    private Optional<Map.Entry<String, AnnotationUsage>> closestClass(ClassType type, List<String> annotationNames,
            Set<String> seen) {
        Optional<JavaSootClass> cls = seen.add(type.getFullyQualifiedName()) ? context.findClass(type)
                : Optional.empty();
        if (cls.isEmpty() || type.getFullyQualifiedName().equals("java.lang.Object")) {
            return Optional.empty();
        }
        Optional<Map.Entry<String, AnnotationUsage>> found = lookup(cls.get(), annotationNames);
        if (found.isPresent()) {
            return found;
        }
        List<ClassType> above = new ArrayList<>();
        cls.get().getSuperclass().ifPresent(above::add);
        above.addAll(cls.get().getInterfaces());
        for (ClassType supertype : above) {
            found = closestClass(supertype, annotationNames, seen);
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    /**
     * Whether a method of a supertype is the one {@code method} overrides: the same name and parameter count, each
     * parameter the same type or one it is assignable to ({@code delete(T)} erased to {@code delete(Object)}, for
     * {@code delete(User)}), not private, and no bridge.
     */
    static boolean overrides(ScanContext context, JavaSootMethod candidate, JavaSootMethod method) {
        if (candidate.isPrivate() || !candidate.getName().equals(method.getName())
                || candidate.getParameterCount() != method.getParameterCount()
                || MethodModifier.isBridge(candidate.getModifiers())) {
            return false;
        }
        for (int i = 0; i < method.getParameterCount(); i++) {
            Type wanted = candidate.getParameterType(i);
            Type actual = method.getParameterType(i);
            boolean assignable = wanted.equals(actual) || wanted instanceof ClassType supertype
                    && actual instanceof ClassType subtype && (supertype.getFullyQualifiedName().equals(
                            "java.lang.Object") || SpringBeans.assignable(context, subtype,
                                    Set.of(supertype.getFullyQualifiedName())));
            if (!assignable) {
                return false;
            }
        }
        return true;
    }

    private Optional<Map.Entry<String, AnnotationUsage>> lookup(HasAnnotation element, List<String> annotationNames) {
        for (String annotationName : annotationNames) {
            Optional<AnnotationUsage> found = lookup(element, annotationName);
            if (found.isPresent()) {
                return Optional.of(Map.entry(annotationName, found.get()));
            }
        }
        return Optional.empty();
    }

    private Optional<AnnotationUsage> lookup(HasAnnotation element, String annotationName) {
        return context.findAnnotation(element, annotationName).map(found -> templated(element, annotationName,
                found));
    }

    /**
     * METHOD-10: with an {@code AnnotationTemplateExpressionDefaults} bean, a pre/post expression on a
     * meta-annotation has its {@code {name}} placeholders replaced by the attributes of the annotation that carries
     * it ({@code @HasRole("ADMIN")} on {@code @PreAuthorize("hasRole('{value}')")}); unknown names stay as written.
     */
    private AnnotationUsage templated(HasAnnotation element, String annotationName, AnnotationUsage found) {
        if (!templates || !SpringNames.PRE_POST.contains(annotationName)
                || !(found.getValues().get("value") instanceof StringConstant expression)) {
            return found;
        }
        for (AnnotationUsage carrier : element.getAnnotations()) {
            String carrierName = Annotations.name(carrier);
            if (carrierName.equals(annotationName)) {
                return found;
            }
            if (!context.metaAnnotations(carrierName).contains(found)) {
                continue;
            }
            Map<String, String> values = new HashMap<>(context.classFiles().annotationDefaults(carrierName));
            carrier.getValues().keySet().forEach(name -> values.put(name,
                    String.join(",", Annotations.strings(carrier, name))));
            String text = expression.getValue();
            for (Map.Entry<String, String> value : values.entrySet()) {
                text = text.replace("{" + value.getKey() + "}", value.getValue());
            }
            Map<String, Object> substituted = new HashMap<>(found.getValues());
            substituted.put("value", new StringConstant(text, expression.getType()));
            return new AnnotationUsage(found.getAnnotation(), substituted);
        }
        return found;
    }

    /**
     * Decision 0091: the check with what its pre/post expression reads: the method's parameters it names (EXPR-02),
     * each a finding when Spring names no parameter so, and the token's claims (EXPR-04).
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private AuthorizationLocation read(JavaSootMethod method, String annotationName, AnnotationUsage annotation,
            AuthorizationLocation location) {
        if (!SpringNames.PRE_POST.contains(annotationName)) {
            return location;
        }
        String expression = Annotations.string(annotation, "value").orElse("");
        List<AuthorizationLocation.Argument> arguments = reads.arguments(method, expression);
        for (AuthorizationLocation.Argument argument : arguments) {
            if (argument.parameter() == null) {
                graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, location.mechanism() + " on "
                        + MethodNames.key(method.getSignature()) + " reads #" + argument.name() + ", but Spring finds no"
                        + " parameter of that name (" + reads.unnamed(method) + "), so #" + argument.name() + " is"
                        + " null when the check runs",
                        location.target()));
            }
        }
        if (!arguments.isEmpty()) {
            withArguments.put(location.id(), method);
        }
        return location.withReads(arguments, ExpressionReads.claims(expression));
    }

    /**
     * Decision 0091: what the request binds into the parameters the checks' expressions name, once the entry points'
     * handlers are known.
     */
    void bindArguments(Set<JavaSootMethod> handlers) {
        withArguments.forEach((id, method) -> graph.find(id).map(AuthorizationLocation.class::cast)
                .ifPresent(location -> graph.replace(location.withReads(location.arguments().stream()
                        .map(argument -> argument.parameter() == null ? argument : argument.withBinding(reads
                                .binding(method, argument.parameter(), handlers))).toList(), location.claims()))));
    }

    private Requirement requirement(String annotationName, AnnotationUsage annotation, SpelRequirements spel,
            SpelRequirements jsr250) {
        if (SpringNames.PRE_POST.contains(annotationName)) {
            return Annotations.string(annotation, "value").map(spel::parse)
                    .orElse(Requirement.expression(""));
        }
        if (annotationName.equals(SpringNames.SECURED)) {
            List<String> authorities = Annotations.strings(annotation, "value");
            return Requirement.anyAuthority(authorities).withSource(String.join(",", authorities));
        }
        if (annotationName.equals(SpringNames.ROLES_ALLOWED)) {
            List<String> roles = Annotations.strings(annotation, "value");
            return Requirement.anyAuthority(roles.stream().map(jsr250::role).toList())
                    .withSource(String.join(",", roles));
        }
        return annotationName.equals(SpringNames.PERMIT_ALL) ? Requirement.permitAll() : Requirement.denyAll();
    }

    /**
     * DENY-02: the method of an application's denial handler that answers when this check denies.
     */
    @Supports(Feature.FIELD_LINEAGE)
    Optional<JavaSootMethod> denialHandler(AuthorizationLocation location) {
        return handlers.getOrDefault(location.id(), Optional.empty());
    }

    /**
     * What 7.1.1 calls: {@code handleDeniedInvocationResult(MethodInvocationResult, ..)} when a post check denies the
     * result (the interface's default delegates to {@code handleDeniedInvocation}), {@code handleDeniedInvocation}
     * when a pre check denies; the handler's own or one it inherits from a class of the application.
     */
    private Optional<JavaSootMethod> handlerMethod(String handler, Phase phase) {
        List<String> names = phase == Phase.POST ? List.of("handleDeniedInvocationResult", "handleDeniedInvocation")
                : List.of("handleDeniedInvocation");
        for (String name : names) {
            Optional<JavaSootClass> cls = context.findClass(handler);
            while (cls.isPresent() && context.isApplication(cls.get().getType())) {
                Optional<JavaSootMethod> found = cls.get().getMethods().stream().filter(method -> method.getName()
                        .equals(name) && method.getParameterCount() == 2 && method.hasBody()
                        && !MethodModifier.isBridge(method.getModifiers())).findFirst();
                if (found.isPresent()) {
                    return found;
                }
                cls = cls.get().getSuperclass().flatMap(context::findClass);
            }
        }
        return Optional.empty();
    }

    /**
     * 7.1.1 {@code PreAuthorizeExpressionAttributeRegistry} and {@code PostAuthorizeExpressionAttributeRegistry}
     * {@code resolveHandler}: under Spring's interceptors, which have the application context, the handler a check
     * names is the one bean of its class, and with none every call of the method fails with an
     * {@code IllegalStateException}. A bean AuthTracer doesn't find may be registered in a way it doesn't read, so the
     * check keeps reading as answering, with a finding.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void unregisteredHandler(JavaSootMethod method, String simpleName, Denial denial) {
        if (denial.handler() == null || beans.isBean(context.type(denial.handler()))) {
            return;
        }
        graph.finding(new Finding(Finding.Kind.OPAQUE_CONFIG, "@HandleAuthorizationDenied on "
                + MethodNames.key(method.getSignature()) + " names " + denial.handler()
                + ", which AuthTracer finds no bean of: Spring Security looks the handler of its " + simpleName
                + " up among the beans and, finding none, fails every call of the method; the graph reads the "
                + "handler as answering the callers it denies", MethodNames.codeRef(method.getSignature())));
    }

    private Denial denial(JavaSootClass cls, JavaSootMethod method, String annotationName) {
        if (annotationName.equals(SpringNames.PRE_FILTER) || annotationName.equals(SpringNames.POST_FILTER)) {
            return new Denial(Denial.Kind.FILTER, null);
        }
        if (!annotationName.equals(SpringNames.PRE_AUTHORIZE) && !annotationName.equals(SpringNames.POST_AUTHORIZE)) {
            // 7.1.1: only those two attribute registries read @HandleAuthorizationDenied; the other managers aren't
            // MethodAuthorizationDeniedHandlers, so the interceptor's default handler throws.
            return Denial.THROW;
        }
        return context.findAnnotation(method, SpringNames.HANDLE_AUTHORIZATION_DENIED)
                .or(() -> context.findAnnotation(cls, SpringNames.HANDLE_AUTHORIZATION_DENIED))
                .flatMap(annotation -> Annotations.className(annotation, "handlerClass"))
                .map(handler -> switch (handler) {
                    case SpringNames.NULL_RETURNING_HANDLER -> new Denial(Denial.Kind.NULL, handler);
                    // The annotation's default handler, named explicitly: 7.1.1's rethrows the denial.
                    case THROWING_HANDLER -> Denial.THROW;
                    default -> new Denial(Denial.Kind.HANDLER, handler);
                })
                .orElse(Denial.THROW);
    }

    /**
     * The JSON property a getter reads, named as the application's Jackson names it, so that a check on it guards
     * the field the response has.
     */
    private Optional<String> getterField(JavaSootMethod method) {
        return method.getParameterCount() != 0 ? Optional.empty()
                : ClassFileMetadata.property(method.getName(), jackson2);
    }
}
