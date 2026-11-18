package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import org.springframework.core.Ordered;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.NullConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.MethodModifier;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * HTTP-17 (decision 0070): the filters and interceptors a request passes before its handler, in the order Spring runs
 * them. A {@code SecurityFilterChain}'s own filters ({@code addFilterBefore/After/At}, {@code addFilter}) run inside
 * Spring Security's filter chain, ordered by 7.1.1's {@code FilterOrderRegistration}, before or after its
 * {@code AuthorizationFilter}; WebFlux's ({@code ServerHttpSecurity.addFilterAt(.., SecurityWebFiltersOrder)}) by
 * {@code SecurityWebFiltersOrder}, around its {@code AUTHORIZATION}. Spring Boot 4.1.1 registers every other
 * {@code Filter} bean for every request ({@code ServletContextInitializerBeans}), unless a {@code FilterRegistrationBean}
 * of it narrows it to its URL patterns or disables it, each at its order (the lowest precedence without one), around
 * Spring Security's own at {@code spring.security.filter.order} (-100); WebFlux runs {@code WebFilter} beans the same
 * way around the -100 of {@code WebFilterChainProxy}. Spring MVC's {@code HandlerInterceptor}s
 * ({@code WebMvcConfigurer#addInterceptors}) run after every filter, for the requests the {@code DispatcherServlet}'s
 * handler mappings serve, in their {@code order(..)}, after the {@code MappedInterceptor} beans.
 *
 * <p>Decision 0070 amended: {@code Customizer<HttpSecurity>} beans' filters are in every chain, Boot's default one
 * too; filters an initializer adds to the servlet context, and a war's web.xml, are registered filters too.
 */
@Supports(Feature.CALL_PATHS)
final class RequestFilters {

    static final String FILTER = "jakarta.servlet.Filter";
    static final String WEB_FILTER = "org.springframework.web.server.WebFilter";
    private static final String ONCE_PER_REQUEST = "org.springframework.web.filter.OncePerRequestFilter";
    private static final String WEB_MVC_CONFIGURER =
            "org.springframework.web.servlet.config.annotation.WebMvcConfigurer";
    private static final String INTERCEPTOR_REGISTRY =
            "org.springframework.web.servlet.config.annotation.InterceptorRegistry";
    private static final String INTERCEPTOR_REGISTRATION =
            "org.springframework.web.servlet.config.annotation.InterceptorRegistration";
    private static final String BOOT_SERVLET = "org.springframework.boot.web.servlet.";
    private static final String FILTER_REGISTRATION = BOOT_SERVLET + "FilterRegistrationBean";
    private static final Set<String> REGISTRATION_TYPES = Set.of(FILTER_REGISTRATION,
            BOOT_SERVLET + "AbstractFilterRegistrationBean", BOOT_SERVLET + "DynamicRegistrationBean",
            BOOT_SERVLET + "RegistrationBean");
    /**
     * Boot 4.1.1's annotation for a filter bean's registration, read by {@code ServletContextInitializerBeans}.
     */
    private static final String FILTER_REGISTRATION_ANNOTATION = BOOT_SERVLET + "FilterRegistration";
    private static final String WEB_FILTER_ANNOTATION = "jakarta.servlet.annotation.WebFilter";
    private static final String SERVLET_CONTEXT_INITIALIZER = BOOT_SERVLET + "ServletContextInitializer";
    private static final String WEB_APPLICATION_INITIALIZER = "org.springframework.web.WebApplicationInitializer";
    private static final String SERVLET_CONTEXT = "jakarta.servlet.ServletContext";
    private static final String FILTER_REGISTRATION_API = "jakarta.servlet.FilterRegistration";
    private static final String MAPPED_INTERCEPTOR = "org.springframework.web.servlet.handler.MappedInterceptor";
    private static final String DELEGATING_FILTER_PROXY = "org.springframework.web.filter.DelegatingFilterProxy";
    private static final String SECURITY_FILTER_NAME = "springSecurityFilterChain";
    private static final String ORDER = "org.springframework.core.annotation.Order";
    private static final String SERVER_HTTP_SECURITY = "org.springframework.security.config.web.server.ServerHttpSecurity";
    private static final Set<String> CHAIN_BUILDERS = Set.of(SpringNames.HTTP_SECURITY,
            "org.springframework.security.config.annotation.web.HttpSecurityBuilder",
            "org.springframework.security.config.annotation.web.HttpSecurityDsl", SERVER_HTTP_SECURITY,
            "org.springframework.security.config.web.server.ServerHttpSecurityDsl");
    private static final Set<String> ADD_FILTER = Set.of("addFilterBefore", "addFilterAfter", "addFilterAt",
            "addFilter");
    private static final Set<String> CUSTOMIZERS = Set.of("org.springframework.security.config.Customizer",
            "org.springframework.security.config.ThrowingCustomizer");
    private static final String WEB = "org.springframework.security.web.";
    /**
     * 7.1.1 {@code FilterOrderRegistration}: each built-in filter's order in a {@code SecurityFilterChain}, 100 apart
     * from 100, two steps skipped. {@code getOrder} also looks up a filter class's superclasses.
     */
    private static final Map<String, Integer> SERVLET_ORDERS = servletOrders();
    private static final String AUTHORIZATION_FILTER = WEB + "access.intercept.AuthorizationFilter";
    /**
     * 7.1.1 {@code SecurityWebFiltersOrder}, in order: each is its ordinal times 100, {@code FIRST} is
     * {@code Integer.MIN_VALUE} and {@code LAST} {@code Integer.MAX_VALUE}.
     */
    private static final List<String> WEB_FILTER_ORDERS = List.of("FIRST", "HTTP_HEADERS_WRITER", "HTTPS_REDIRECT",
            "CORS", "CSRF", "REACTOR_CONTEXT", "HTTP_BASIC", "FORM_LOGIN", "AUTHENTICATION", "ANONYMOUS_AUTHENTICATION",
            "OAUTH2_AUTHORIZATION_CODE", "LOGIN_PAGE_GENERATING", "LOGOUT_PAGE_GENERATING", "ONE_TIME_TOKEN",
            "ONE_TIME_TOKEN_SUBMIT_PAGE_GENERATING", "SECURITY_CONTEXT_SERVER_WEB_EXCHANGE", "SERVER_REQUEST_CACHE",
            "LOGOUT", "EXCEPTION_TRANSLATION", "AUTHORIZATION", "LAST");
    /**
     * Boot's {@code SecurityFilterProperties.DEFAULT_FILTER_ORDER}, and WebFlux's
     * {@code WebFluxSecurityConfiguration.WEB_FILTER_CHAIN_FILTER_ORDER}.
     */
    private static final int SECURITY_ORDER = -100;

    /**
     * Application code Spring calls for a request, on an object of {@code receiver} ({@code null} for a lambda).
     *
     * @param methods what Spring calls, in order
     * @param conditional it may not run for a request it covers: its {@code shouldNotFilter} decides, or the library
     *        filter it extends calls these methods for some requests only
     * @param once a {@code OncePerRequestFilter}
     */
    record Code(String name, ClassType receiver, List<JavaSootMethod> methods, boolean conditional, boolean once) {

        Code with(List<JavaSootMethod> some) {
            return new Code(name, receiver, some, conditional, once);
        }
    }

    /**
     * One filter or interceptor a request passes: its code, or, when AuthTracer can't tell what it is,
     * {@code unresolved} says what it is and {@code site} where it is registered.
     *
     * @param bean the filter is a bean, which a {@code OncePerRequestFilter} registered twice runs as one
     * @param maybe it may not be on the request's way: its URL patterns, or the chain it is in, may not take it
     */
    record Pass(Code code, String unresolved, CodeRef site, boolean bean, boolean maybe) {

        Pass(Code code, String unresolved, CodeRef site, boolean bean) {
            this(code, unresolved, site, bean, false);
        }

        Pass asConditional() {
            return new Pass(code, unresolved, site, bean, true);
        }

        /**
         * It may not run for the request.
         */
        boolean conditional() {
            return maybe || code != null && code.conditional();
        }
    }

    /**
     * What a request passes: around its filter chain's rule, then around its handler.
     */
    record Around(List<Pass> beforeRule, List<Pass> afterRule, List<Pass> beforeHandler, List<Pass> afterHandler) {

        static final Around NONE = new Around(List.of(), List.of(), List.of(), List.of());
    }

    /**
     * A filter the servlet container (or WebFlux's handler) runs for the requests its URL patterns match.
     *
     * @param urls servlet URL patterns ({@code /*}, {@code /api/*}, {@code *.do}, exact); {@code null} when they can't
     *        be read, so the filter may run for any request
     */
    private record Registered(Pass pass, int order, List<String> urls) {
    }

    /**
     * A filter added to a {@code SecurityFilterChain}, before or after its authorization filter.
     */
    private record Chained(Pass pass, boolean beforeAuthorization) {
    }

    /**
     * An interceptor's registration: {@code null} patterns when they can't be read.
     */
    private record Interceptor(Pass before, Pass post, Pass completion, int order, List<String> include,
            List<String> exclude) {
    }

    /**
     * A filter or interceptor value resolved: its code, or why it isn't known; both {@code null} for a library's own
     * filter, which runs Spring's or the library's code only.
     *
     * @param bean the value is the bean itself (injected, or a bean method's), not an object made where it is used
     */
    private record Resolved(Code code, String unresolved, ClassType type, boolean bean) {

        static final Resolved LIBRARY = new Resolved(null, null, null, false);

        Optional<Pass> pass(CodeRef site) {
            return code == null && unresolved == null ? Optional.empty()
                    : Optional.of(new Pass(code, unresolved, site, bean));
        }

        Resolved asBean() {
            return new Resolved(code, unresolved, type, true);
        }
    }

    private enum Kind {
        FILTER, WEB_FILTER, INTERCEPTOR, INITIALIZER
    }

    /**
     * A library filter that authenticates, added by hand: it runs Spring's code only, so it is no step, but it is a way
     * in (decision 0071 amended).
     *
     * @param beforeRule some request passes it before its chain's rule
     */
    @Supports(Feature.AUTHORITY_SOURCE)
    record Library(ClassType type, boolean beforeRule, CodeRef site) {

        String name() {
            return type.getClassName();
        }
    }

    private final ScanContext context;
    private final SpringBeans beans;
    private final boolean reactive;
    private final CallTraversal calls;
    private final Map<String, List<Chained>> chains = new HashMap<>();
    /**
     * What the {@code Customizer<HttpSecurity>} beans add to the chain Spring Boot (or Spring Security) builds when
     * the application declares none.
     */
    private List<Chained> defaultChain = List.of();
    private final List<Registered> registered = new ArrayList<>();
    /**
     * {@code MappedInterceptor} beans, which every handler mapping detects and runs before the ones it is given.
     */
    private final List<Interceptor> mapped = new ArrayList<>();
    private final List<Interceptor> interceptors = new ArrayList<>();
    private final List<Library> authenticating = new ArrayList<>();
    private final List<Finding> findings = new ArrayList<>();
    private final int securityOrder;
    private final String servletPath;

    RequestFilters(ScanContext context, SpringBeans beans, boolean reactive) {
        this.context = context;
        this.beans = beans;
        this.reactive = reactive;
        this.calls = new CallTraversal(context);
        this.securityOrder = reactive ? SECURITY_ORDER : context.properties().get("spring.security.filter.order")
                .map(String::trim).filter(order -> order.matches("-?\\d+")).map(Integer::parseInt)
                .orElse(SECURITY_ORDER);
        this.servletPath = context.properties().get("spring.mvc.servlet.path")
                .map(path -> ("/" + path).replaceAll("/+", "/").replaceAll("/$", "")).orElse("");
        readChains();
        if (reactive) {
            readWebFilters();
        }
        else {
            readServletFilters();
            readServletContextFilters();
            readWebXml();
            readInterceptors();
            readMappedInterceptors();
        }
        registered.sort(Comparator.comparingInt(Registered::order));
        interceptors.sort(Comparator.comparingInt(Interceptor::order));
    }

    /**
     * The filters and interceptors of a request.
     *
     * @param chains the {@code SecurityFilterChain} bean methods that may handle it, in order, and whether it surely
     *        passes them
     * @param dispatched whether the {@code DispatcherServlet}'s handler mappings serve it, so its interceptors run
     * @param mappedOnly a handler mapping of the {@code DispatcherServlet}'s that isn't given the
     *        {@code InterceptorRegistry}'s interceptors serves it (a WebSocket handshake): only the
     *        {@code MappedInterceptor} beans run
     * @param ownServlet a servlet of its own serves it (gRPC's), mapped on the whole path
     */
    Around around(Ingress request, HttpSecurityRules.Passes chains, boolean dispatched, boolean mappedOnly,
            boolean ownServlet) {
        List<Pass> beforeRule = new ArrayList<>();
        List<Pass> afterRule = new ArrayList<>();
        List<Pass> afterChain = new ArrayList<>();
        String path = (ownServlet || ownServlet(request) ? "" : servletPath) + request.route();
        for (Registered filter : registered) {
            Coverage covers = filter.urls() == null ? Coverage.MAYBE : covers(filter.urls(), path);
            if (covers != Coverage.NO) {
                Pass pass = covers == Coverage.MAYBE ? filter.pass().asConditional() : filter.pass();
                (filter.order() < securityOrder ? beforeRule : afterChain).add(pass);
            }
        }
        for (MethodSignature chain : chains.chains()) {
            for (Chained filter : this.chains.getOrDefault(MethodNames.key(chain), List.of())) {
                Pass pass = chains.surely() ? filter.pass() : filter.pass().asConditional();
                (filter.beforeAuthorization() ? beforeRule : afterRule).add(pass);
            }
        }
        // The default chain takes every request ignoring() doesn't.
        if (chains.chains().isEmpty() && !chains.surely()) {
            defaultChain.forEach(filter -> (filter.beforeAuthorization() ? beforeRule : afterRule).add(filter.pass()));
        }
        afterRule.addAll(afterChain);
        List<Pass> beforeHandler = new ArrayList<>();
        List<Pass> postHandle = new ArrayList<>();
        List<Pass> afterCompletion = new ArrayList<>();
        // AbstractHandlerMapping#initApplicationContext: the MappedInterceptor beans it detects, then those it is given.
        List<Interceptor> run = new ArrayList<>(dispatched || mappedOnly ? mapped : List.of());
        if (dispatched) {
            run.addAll(interceptors);
        }
        for (Interceptor interceptor : run) {
            Coverage covers = covers(interceptor, request);
            if (covers != Coverage.NO) {
                add(beforeHandler, interceptor.before(), covers);
                add(postHandle, interceptor.post(), covers);
                add(afterCompletion, interceptor.completion(), covers);
            }
        }
        // HandlerExecutionChain: every postHandle, then every afterCompletion, each in reverse order.
        List<Pass> afterHandler = new ArrayList<>(postHandle.reversed());
        afterHandler.addAll(afterCompletion.reversed());
        List<Pass> before = once(beforeRule, new HashSet<>());
        return new Around(before, once(afterRule, before.stream().filter(RequestFilters::once)
                .map(pass -> pass.code().receiver()).collect(java.util.stream.Collectors.toSet())), beforeHandler,
                afterHandler);
    }

    /**
     * Every filter some request passes, for the ways in they add (decision 0071).
     */
    @Supports(Feature.AUTHORITY_SOURCE)
    List<Code> filters() {
        List<Code> all = new ArrayList<>();
        registered.forEach(filter -> Optional.ofNullable(filter.pass().code()).ifPresent(all::add));
        chained().forEach(filter -> Optional.ofNullable(filter.pass().code()).ifPresent(all::add));
        return all;
    }

    /**
     * The library filters that authenticate, added to a chain or registered by hand (decision 0071 amended).
     */
    @Supports(Feature.AUTHORITY_SOURCE)
    List<Library> authenticating() {
        return authenticating;
    }

    /**
     * OPAQUE_CONFIG for a web.xml AuthTracer couldn't read.
     */
    List<Finding> findings() {
        return findings;
    }

    private List<Chained> chained() {
        List<Chained> all = new ArrayList<>(defaultChain);
        chains.values().forEach(all::addAll);
        return all;
    }

    /**
     * Whether some request passes the filter before its chain's rule: one that runs only after it (added after the
     * {@code AuthorizationFilter}, or registered after Spring Security's filter) authenticates too late for the rule,
     * which has decided for a caller who hadn't signed in.
     */
    @Supports(Feature.AUTHORITY_SOURCE)
    boolean beforeRule(String name) {
        return registered.stream().anyMatch(filter -> named(filter.pass(), name) && filter.order() < securityOrder)
                || chained().stream().anyMatch(filter -> named(filter.pass(), name) && filter.beforeAuthorization());
    }

    private static boolean named(Pass pass, String name) {
        return pass.code() != null && pass.code().name().equals(name);
    }

    private static void add(List<Pass> passes, Pass pass, Coverage covers) {
        if (pass != null) {
            passes.add(covers == Coverage.MAYBE ? pass.asConditional() : pass);
        }
    }

    /**
     * A {@code OncePerRequestFilter} bean that runs twice, as Boot registers it and in a chain, does its work the
     * first time only: the second sees its request attribute, named after the bean.
     *
     * @param seen the beans that ran already
     */
    private static List<Pass> once(List<Pass> passes, Set<ClassType> seen) {
        List<Pass> kept = new ArrayList<>();
        for (Pass pass : passes) {
            if (!once(pass) || seen.add(pass.code().receiver())) {
                kept.add(pass);
            }
        }
        return kept;
    }

    private static boolean once(Pass pass) {
        return pass.bean() && pass.code() != null && pass.code().once();
    }

    private boolean ownServlet(Ingress request) {
        return request.handler() != null && SpringBeans.assignable(context, context.type(request.handler()
                .className()), Set.of("jakarta.servlet.http.HttpServlet"));
    }

    // The SecurityFilterChain's own filters.

    private void readChains() {
        // 7.1.1 HttpSecurityConfiguration#applyHttpSecurityCustomizers (ServerHttpSecurityConfiguration's for
        // WebFlux): the Customizer<HttpSecurity> beans, in @Order, configure the prototype HttpSecurity every chain is
        // built from, Spring Boot's default one too, before the chain's bean method does.
        List<Map.Entry<Integer, Chained>> customized = new ArrayList<>();
        Map<String, Integer> customOrders = new HashMap<>();
        for (JavaSootMethod customizer : customizers()) {
            readChain(customizer, customized, customOrders, new HashSet<>(), 0);
        }
        // A chain of the web stack the application does not run never runs (#48).
        List<JavaSootMethod> declared = SpringBeans.beanMethodsOf(context, Set.of(reactive
                ? WebStack.SECURITY_WEB_FILTER_CHAIN : WebStack.SECURITY_FILTER_CHAIN));
        for (JavaSootMethod chain : declared) {
            List<Map.Entry<Integer, Chained>> added = new ArrayList<>(customized);
            readChain(chain, added, new HashMap<>(customOrders), new HashSet<>(), 0);
            chains.put(MethodNames.key(chain.getSignature()), sorted(added));
        }
        if (declared.isEmpty()) {
            defaultChain = sorted(customized);
        }
    }

    /**
     * {@code HttpSecurity#performBuild} and {@code ServerHttpSecurity#build} sort them, stably: the chain's own come
     * before the configurers' at the same order, its AuthorizationFilter among them.
     */
    private static List<Chained> sorted(List<Map.Entry<Integer, Chained>> added) {
        List<Map.Entry<Integer, Chained>> sorted = new ArrayList<>(added);
        sorted.sort(Map.Entry.comparingByKey());
        return sorted.stream().map(Map.Entry::getValue).toList();
    }

    /**
     * The {@code Customizer<HttpSecurity>} (and {@code ThrowingCustomizer}) bean methods, in {@code @Order}.
     */
    private List<JavaSootMethod> customizers() {
        String builder = reactive ? SERVER_HTTP_SECURITY : SpringNames.HTTP_SECURITY;
        List<JavaSootMethod> customizers = new ArrayList<>(SpringBeans.beanMethods(context, CUSTOMIZERS).stream()
                .filter(method -> method.hasBody() && context.classFiles().genericReturnType(method.getSignature())
                        .filter(generic -> !generic.arguments().isEmpty()
                                && generic.arguments().getFirst().name().equals(builder)).isPresent())
                .toList());
        customizers.sort(Comparator.comparingInt(method -> HttpSecurityRules.order(context, method)));
        return customizers;
    }

    /**
     * The {@code addFilter*} calls in the chain's bean method and the helpers and lambdas it calls, in order.
     *
     * @param custom the order each filter class added so far was given: later calls may place others relative to it
     */
    private void readChain(JavaSootMethod method, List<Map.Entry<Integer, Chained>> added,
            Map<String, Integer> custom, Set<String> seen, int depth) {
        if (!method.hasBody() || depth > 4 || !seen.add(method.getSignature().toString())) {
            return;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty()) {
                continue;
            }
            String declaring = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.get().getMethodSignature().getName();
            if (CHAIN_BUILDERS.contains(declaring) && ADD_FILTER.contains(name)) {
                Resolved filter = resolve(method, invoke.get().getArg(0), reactive ? Kind.WEB_FILTER : Kind.FILTER);
                Integer order = reactive ? webFilterOrder(method, name, invoke.get())
                        : servletOrder(name, invoke.get(), filter, custom);
                if (!reactive && order != null && filter.type() != null) {
                    custom.putIfAbsent(filter.type().getFullyQualifiedName(), order);
                }
                int authorization = reactive ? WEB_FILTER_ORDERS.indexOf("AUTHORIZATION") * 100
                        : SERVLET_ORDERS.get(AUTHORIZATION_FILTER);
                // Spring refuses a position it doesn't know at startup; read it as before the rule.
                int at = order == null ? authorization : order;
                CodeRef site = MethodNames.codeRef(method.getSignature(), stmt);
                filter.pass(site).ifPresent(pass -> added.add(Map.entry(at, new Chained(pass, at <= authorization))));
                library(filter, at <= authorization, site);
                continue;
            }
            for (JavaSootMethod target : calls.targets(invoke.get())) {
                readChain(target, added, custom, seen, depth + 1);
            }
        }
    }

    /**
     * A library filter that authenticates, added by hand ({@code addFilter(new RequestHeaderAuthenticationFilter())},
     * a {@code BearerTokenAuthenticationFilter} built in code, a filter bean of one): a way in.
     */
    @Supports(Feature.AUTHORITY_SOURCE)
    private void library(Resolved filter, boolean beforeRule, CodeRef site) {
        if (filter.code() == null && filter.unresolved() == null && filter.type() != null
                && FilterAuthentication.authenticates(context, filter.type())) {
            authenticating.add(new Library(filter.type(), beforeRule, site));
        }
    }

    /**
     * {@code HttpSecurity#addFilterAtOffsetOf}: the order of the class the filter is placed at, -1 before it and +1
     * after it; {@code addFilter(filter)} takes the filter class's own.
     */
    private Integer servletOrder(String name, AbstractInvokeExpr invoke, Resolved filter, Map<String, Integer> custom) {
        if (name.equals("addFilter")) {
            return filter.type() == null ? null : servletOrder(filter.type().getFullyQualifiedName(), custom);
        }
        Integer order = GroovyCalls.className(invoke.getArg(1)).map(className -> servletOrder(className, custom))
                .orElse(null);
        if (order == null) {
            return null;
        }
        return name.equals("addFilterBefore") ? order - 1 : name.equals("addFilterAfter") ? order + 1 : order;
    }

    private Integer servletOrder(String className, Map<String, Integer> custom) {
        List<String> chain = new ArrayList<>(List.of(className));
        context.superClassesOf(context.type(className)).forEach(type -> chain.add(type.getFullyQualifiedName()));
        for (String candidate : chain) {
            Integer order = SERVLET_ORDERS.getOrDefault(candidate, custom.get(candidate));
            if (order != null) {
                return order;
            }
        }
        return null;
    }

    /**
     * {@code ServerHttpSecurity#addFilterBefore}: the position's order -1, {@code addFilterAfter} +1, as ints.
     */
    private Integer webFilterOrder(JavaSootMethod method, String name, AbstractInvokeExpr invoke) {
        Value position = invoke.getArg(1) instanceof Local local
                ? Locals.definition(method.getBody(), local).orElse(local) : invoke.getArg(1);
        if (!(position instanceof JStaticFieldRef field)) {
            return null;
        }
        int index = WEB_FILTER_ORDERS.indexOf(field.getFieldSignature().getName());
        if (index < 0) {
            return null;
        }
        int order = index == 0 ? Integer.MIN_VALUE : index == WEB_FILTER_ORDERS.size() - 1 ? Integer.MAX_VALUE
                : index * 100;
        return name.equals("addFilterBefore") ? order - 1 : name.equals("addFilterAfter") ? order + 1 : order;
    }

    // Filters the servlet container runs.

    /**
     * The bean methods in the order Spring defines their beans, which breaks ties of order: by class, then as
     * declared.
     */
    private List<JavaSootMethod> beanMethods() {
        return SpringBeans.beanMethods(context).stream().filter(JavaSootMethod::hasBody)
                .sorted(Comparator.comparing((JavaSootMethod method) -> method.getDeclaringClassType()
                        .getFullyQualifiedName()).thenComparingInt(method -> method.getBody().getStmts().stream()
                                .mapToInt(stmt -> stmt.getPositionInfo().getStmtPosition().getFirstLine())
                                .filter(line -> line > 0).min().orElse(0)))
                .toList();
    }

    /**
     * {@code ServletContextInitializerBeans}: the registration beans first ({@code FilterRegistrationBean}s, and
     * those {@code @WebFilter} classes get), then every other filter bean; sorted by order, stably.
     */
    private void readServletFilters() {
        // The filter beans a registration of the bean itself takes over: Boot doesn't register them again.
        Set<ClassType> taken = new HashSet<>();
        for (JavaSootMethod method : beanMethods()) {
            if (method.getReturnType() instanceof ClassType type
                    && type.getFullyQualifiedName().equals(FILTER_REGISTRATION)) {
                registration(method, taken).ifPresent(registered::add);
            }
        }
        List<JavaSootClass> filters = context.applicationClasses().stream().filter(cls -> !cls.isInterface()
                && !cls.isAbstract() && SpringBeans.assignable(context, cls.getType(), Set.of(FILTER))).toList();
        ServletEndpoints.Discovery discovery = ServletEndpoints.discovery(context);
        if (discovery != ServletEndpoints.Discovery.NONE) {
            // Boot's WebFilterHandler registers a FilterRegistrationBean for each, at the lowest precedence; a
            // container that reads them itself maps them after the filters an initializer adds, Spring Security's
            // among them. A Boot war's may not run (ServletEndpoints.discovery).
            boolean maybe = discovery == ServletEndpoints.Discovery.WAR;
            for (JavaSootClass cls : filters) {
                context.findAnnotation(cls, WEB_FILTER_ANNOTATION).ifPresent(annotation -> {
                    List<String> urls = new ArrayList<>(Annotations.strings(annotation, "urlPatterns"));
                    urls.addAll(Annotations.strings(annotation, "value"));
                    boolean servletNames = !Annotations.strings(annotation, "servletNames").isEmpty();
                    typed(cls.getType(), Kind.FILTER, false).pass(CodeRef.ofClass(cls.getName())).ifPresent(pass ->
                            registered.add(new Registered(maybe ? pass.asConditional() : pass,
                                    Ordered.LOWEST_PRECEDENCE, servletNames ? null
                                            : !urls.isEmpty() ? urls : List.of("/*"))));
                    if (maybe) {
                        findings.add(ServletEndpoints.warFinding("@WebFilter", cls, "it is shown as a filter that may"
                                + " not run"));
                    }
                });
            }
        }
        for (JavaSootMethod method : beanMethods()) {
            if (method.getReturnType() instanceof ClassType type
                    && SpringBeans.assignable(context, type, Set.of(FILTER))) {
                Resolved filter = beanReturned(method, Kind.FILTER);
                if (filter.type() == null || !taken.contains(filter.type())) {
                    bean(method, method.getAnnotations(), filter);
                }
            }
        }
        for (JavaSootClass cls : filters) {
            if (context.hasAnnotation(cls, SpringNames.COMPONENT) && !taken.contains(cls.getType())) {
                bean(null, cls.getAnnotations(), typed(cls.getType(), Kind.FILTER, true));
            }
        }
    }

    /**
     * A filter bean Boot registers: for every request at its order, unless {@code @FilterRegistration} says otherwise.
     *
     * @param method its bean method, {@code null} for a component
     */
    private void bean(JavaSootMethod method, Iterable<AnnotationUsage> annotations, Resolved filter) {
        CodeRef site = method != null ? MethodNames.codeRef(method.getSignature())
                : CodeRef.ofClass(filter.type().getFullyQualifiedName());
        Optional<Pass> pass = filter.pass(site);
        if (pass.isEmpty()) {
            // A library filter bean: at the lowest precedence unless its class orders it.
            Integer order = instanceOrder(filter.type());
            library(filter, order != null && order < securityOrder, site);
            return;
        }
        Optional<AnnotationUsage> registration = method == null
                ? context.findClass(filter.type()).flatMap(cls -> context.findAnnotation(cls,
                        FILTER_REGISTRATION_ANNOTATION))
                : context.findAnnotation(method, FILTER_REGISTRATION_ANNOTATION);
        if (registration.flatMap(found -> Annotations.bool(found, "enabled")).orElse(true).equals(false)) {
            return;
        }
        List<String> urls = registration.map(found -> Annotations.strings(found, "urlPatterns"))
                .filter(found -> !found.isEmpty()).orElse(List.of("/*"));
        if (registration.isPresent() && !Annotations.strings(registration.get(), "servletNames").isEmpty()) {
            // Mapped by servlet name too: any request may reach it.
            urls = null;
        }
        Integer order = reactive ? first(order(annotations), instanceOrder(filter.type()))
                : first(instanceOrder(filter.type()), registration.map(found -> first(order(annotations),
                        Annotations.integer(found, "order").orElse(null))).orElse(null));
        registered.add(new Registered(pass.get(), order == null ? Ordered.LOWEST_PRECEDENCE : order, urls));
    }

    /**
     * Boot 4.1.1 orders a filter bean by the object ({@code ServletContextInitializerBeans#findOrder}:
     * {@code Ordered}, else {@code @Order} on its class), else by {@code @FilterRegistration}'s order (an
     * {@code @Order} beside it, or its own): an {@code @Order} on a {@code @Bean} method alone is not read. WebFlux's
     * {@code orderedStream()} reads the bean method's {@code @Order} first.
     */
    private Integer instanceOrder(ClassType type) {
        if (type == null) {
            return null;
        }
        Integer ordered = own(type, "getOrder").filter(method -> method.getParameterCount() == 0)
                .flatMap(method -> method.getBody().getStmts().stream()
                        .filter(JReturnStmt.class::isInstance).map(stmt -> ((JReturnStmt) stmt).getOp())
                        .filter(IntConstant.class::isInstance).map(constant -> ((IntConstant) constant).getValue())
                        .findFirst())
                .orElse(null);
        if (ordered != null) {
            return ordered;
        }
        List<ClassType> hierarchy = new ArrayList<>(List.of(type));
        hierarchy.addAll(context.superClassesOf(type));
        return hierarchy.stream().flatMap(candidate -> context.findClass(candidate).stream())
                .map(cls -> order(cls.getAnnotations())).filter(java.util.Objects::nonNull).findFirst().orElse(null);
    }

    private static Integer first(Integer order, Integer otherwise) {
        return order != null ? order : otherwise;
    }

    private static Integer order(Iterable<AnnotationUsage> annotations) {
        for (AnnotationUsage annotation : annotations) {
            if (Annotations.name(annotation).equals(ORDER)) {
                return Annotations.integer(annotation, "value").orElse(Ordered.LOWEST_PRECEDENCE);
            }
        }
        return null;
    }

    /**
     * A {@code FilterRegistrationBean} bean method: {@code new FilterRegistrationBean<>(filter)} or
     * {@code setFilter(..)}, {@code addUrlPatterns(..)}/{@code setUrlPatterns(..)} (none is {@code /*}),
     * {@code setOrder(..)} (one it can't read is ahead of Spring Security's), {@code setEnabled(..)} (one it can't
     * read may turn it off), and servlet names (any request, as AuthTracer reads them).
     */
    private Optional<Registered> registration(JavaSootMethod method, Set<ClassType> taken) {
        Resolved filter = Resolved.LIBRARY;
        List<String> urls = new ArrayList<>();
        boolean unread = false;
        boolean servletNames = false;
        Boolean enabled = true;
        int order = Ordered.LOWEST_PRECEDENCE;
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty() || !REGISTRATION_TYPES.contains(invoke.get().getMethodSignature().getDeclClassType()
                    .getFullyQualifiedName())) {
                continue;
            }
            String name = invoke.get().getMethodSignature().getName();
            List<Immediate> args = invoke.get().getArgs();
            if ((name.equals("<init>") || name.equals("setFilter")) && !args.isEmpty()) {
                filter = resolve(method, args.getFirst(), Kind.FILTER);
            }
            else if (name.equals("addUrlPatterns") || name.equals("setUrlPatterns")) {
                Optional<List<String>> read = ServletEndpoints.mappings(method, args.getFirst());
                read.ifPresent(urls::addAll);
                unread |= read.isEmpty();
            }
            else if (name.equals("addServletNames") || name.equals("setServletNames")
                    || name.equals("addServletRegistrationBeans") || name.equals("setServletRegistrationBeans")) {
                servletNames = true;
            }
            else if (name.equals("setOrder")) {
                // An order AuthTracer can't read may put the filter ahead of Spring Security's: the weaker reading,
                // since then requests the rules deny reach it too.
                order = args.getFirst() instanceof IntConstant constant ? constant.getValue() : Integer.MIN_VALUE;
            }
            else if (name.equals("setEnabled")) {
                // One AuthTracer can't read may turn the filter off: it may run.
                enabled = args.getFirst() instanceof IntConstant flag ? Boolean.valueOf(flag.getValue() != 0) : null;
            }
        }
        if (filter.bean() && filter.type() != null) {
            taken.add(filter.type());
        }
        Optional<Pass> pass = filter.pass(MethodNames.codeRef(method.getSignature()));
        if (Boolean.FALSE.equals(enabled)) {
            return Optional.empty();
        }
        if (pass.isEmpty()) {
            library(filter, order < securityOrder, MethodNames.codeRef(method.getSignature()));
            return Optional.empty();
        }
        // AbstractFilterRegistrationBean#configure maps a registration without URL patterns or servlet names to /*,
        // and one with servlet names to them as well as to its patterns.
        List<String> patterns = unread || servletNames ? null : urls.isEmpty() ? List.of("/*") : urls;
        return Optional.of(new Registered(enabled == null ? pass.get().asConditional() : pass.get(), order,
                patterns));
    }

    private enum Coverage {
        YES, MAYBE, NO
    }

    /**
     * Servlet URL patterns (Servlet 6 12.2) against a route: {@code /*}; a prefix {@code /api/*}, which also matches
     * {@code /api}; an extension {@code *.do}; an exact path. A template variable or {@code **} in the route may be
     * what a pattern names.
     */
    private static Coverage covers(List<String> patterns, String path) {
        Coverage best = Coverage.NO;
        for (String pattern : patterns) {
            Coverage covers = covers(pattern, path);
            if (covers == Coverage.YES) {
                return covers;
            }
            if (covers == Coverage.MAYBE) {
                best = covers;
            }
        }
        return best;
    }

    private static Coverage covers(String pattern, String path) {
        if (pattern.equals("/*") || pattern.equals("/")) {
            return Coverage.YES;
        }
        String[] segments = path.split("/", -1);
        String last = segments[segments.length - 1];
        if (pattern.startsWith("*.")) {
            return last.endsWith(pattern.substring(1)) ? Coverage.YES : variable(last) ? Coverage.MAYBE
                    : Coverage.NO;
        }
        boolean prefix = pattern.endsWith("/*");
        String[] wanted = (prefix ? pattern.substring(0, pattern.length() - 2) : pattern).split("/", -1);
        Coverage result = Coverage.YES;
        for (int i = 0; i < wanted.length; i++) {
            if (i >= segments.length) {
                return Coverage.NO;
            }
            if (segments[i].equals("**")) {
                return Coverage.MAYBE;
            }
            if (!segments[i].equals(wanted[i])) {
                if (!variable(segments[i])) {
                    return Coverage.NO;
                }
                result = Coverage.MAYBE;
            }
        }
        return prefix || segments.length == wanted.length ? result : Coverage.NO;
    }

    private static boolean variable(String segment) {
        return segment.startsWith("{") || segment.contains("*");
    }

    // WebFlux's filters.

    /**
     * {@code WebHttpHandlerBuilder#applicationContext}: every {@code WebFilter} bean, in {@code @Order}.
     */
    private void readWebFilters() {
        for (JavaSootMethod method : beanMethods()) {
            if (method.getReturnType() instanceof ClassType type
                    && SpringBeans.assignable(context, type, Set.of(WEB_FILTER))) {
                bean(method, method.getAnnotations(), beanReturned(method, Kind.WEB_FILTER));
            }
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!cls.isInterface() && !cls.isAbstract() && context.hasAnnotation(cls, SpringNames.COMPONENT)
                    && SpringBeans.assignable(context, cls.getType(), Set.of(WEB_FILTER))) {
                bean(null, cls.getAnnotations(), typed(cls.getType(), Kind.WEB_FILTER, true));
            }
        }
    }

    // Filters given to the servlet context in code.

    /**
     * {@code ServletContext#addFilter(name, filter)} in a {@code ServletContextInitializer} bean (a lambda, or a class
     * of the application's) or component, which Spring Boot 4.1.1 runs among its registration beans, and in a
     * {@code WebApplicationInitializer}, which a servlet container runs for a war: its
     * place against Spring Security's filter isn't read, so it is read as ahead of it (the weaker reading).
     */
    private void readServletContextFilters() {
        List<Map.Entry<Integer, Resolved>> plain = new ArrayList<>();
        for (JavaSootMethod bean : beanMethods()) {
            if (bean.getReturnType() instanceof ClassType type
                    && SpringBeans.assignable(context, type, Set.of(SERVLET_CONTEXT_INITIALIZER))) {
                for (Resolved initializer : returnedAll(bean)) {
                    plain.add(Map.entry(orderOf(instanceOrder(initializer.type())), initializer));
                }
            }
        }
        List<Resolved> war = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (cls.isInterface() || cls.isAbstract()) {
                continue;
            }
            if (context.hasAnnotation(cls, SpringNames.COMPONENT)
                    && SpringBeans.assignable(context, cls.getType(), Set.of(SERVLET_CONTEXT_INITIALIZER))) {
                plain.add(Map.entry(orderOf(instanceOrder(cls.getType())), typed(cls.getType(), Kind.INITIALIZER,
                        true)));
            }
            else if (SpringBeans.assignable(context, cls.getType(), Set.of(WEB_APPLICATION_INITIALIZER))) {
                war.add(typed(cls.getType(), Kind.INITIALIZER, false));
            }
        }
        // ServletContextInitializerBeans groups the initializer beans by what they register (servlets, filters,
        // listeners, anything else), puts each group where its first bean comes in order, and sorts within a group:
        // the plain initializers' filters come before every filter registration, Spring Security's among them, when
        // the first of them comes before Spring Security's, and after them all otherwise. A tie, or a filter
        // registration of the application's ahead of it (not read), is read as before (the weaker reading).
        plain.sort(Map.Entry.comparingByKey());
        int group = !plain.isEmpty() && plain.getFirst().getKey() <= securityOrder ? Integer.MIN_VALUE
                : Ordered.LOWEST_PRECEDENCE;
        plain.forEach(initializer -> initialized(initializer.getValue(), group));
        war.forEach(initializer -> initialized(initializer, Integer.MIN_VALUE));
    }

    /**
     * {@code Ordered} or {@code @Order} on an object's class, else the lowest precedence (a lambda's).
     */
    private static int orderOf(Integer order) {
        return order == null ? Ordered.LOWEST_PRECEDENCE : order;
    }

    /**
     * A war's web.xml filters ({@link WebXml}): after Spring Security's filter, unless the file maps it (a
     * {@code DelegatingFilterProxy} named {@code springSecurityFilterChain}) after them. A
     * {@code DelegatingFilterProxy} to another bean runs that bean.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void readWebXml() {
        WebXml.Config xml = WebXml.load(context.input().resourceDirs());
        xml.unread().ifPresent(file -> findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "AuthTracer couldn't"
                + " read " + file + ", so the filters it maps aren't on any request's path", null)));
        boolean security = xml.mappings().stream().anyMatch(RequestFilters::isSecurityFilter);
        int at = security ? Integer.MIN_VALUE : Ordered.LOWEST_PRECEDENCE;
        for (WebXml.Mapping mapping : xml.mappings()) {
            if (isSecurityFilter(mapping)) {
                at = Ordered.LOWEST_PRECEDENCE;
                continue;
            }
            CodeRef site = CodeRef.ofClass(mapping.className());
            Resolved filter = mapping.className().equals(DELEGATING_FILTER_PROXY) ? delegated(mapping.targetBean())
                    : typed(context.type(mapping.className()), Kind.FILTER, false);
            int order = at;
            filter.pass(site).ifPresentOrElse(pass -> registered.add(new Registered(pass, order, mapping.urls())),
                    () -> library(filter, order < securityOrder, site));
        }
    }

    private static boolean isSecurityFilter(WebXml.Mapping mapping) {
        return mapping.className().equals(DELEGATING_FILTER_PROXY)
                && mapping.targetBean().equals(SECURITY_FILTER_NAME);
    }

    /**
     * The filter bean a {@code DelegatingFilterProxy} runs: a bean method or component of that name.
     */
    private Resolved delegated(String name) {
        for (JavaSootMethod bean : beanMethods()) {
            if (bean.getName().equals(name)) {
                return returnedAll(bean, Kind.FILTER).stream().findFirst().orElse(Resolved.LIBRARY).asBean();
            }
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!cls.isInterface() && context.hasAnnotation(cls, SpringNames.COMPONENT)
                    && SpringBeans.beanName(context, cls).equals(name)) {
                return typed(cls.getType(), Kind.FILTER, true);
            }
        }
        return new Resolved(null, "the bean " + name + ", which a DelegatingFilterProxy in web.xml runs", null, true);
    }

    private List<Resolved> returnedAll(JavaSootMethod method) {
        return returnedAll(method, Kind.INITIALIZER);
    }

    private List<Resolved> returnedAll(JavaSootMethod method, Kind kind) {
        return method.getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                .map(stmt -> resolve(method, ((JReturnStmt) stmt).getOp(), kind)).distinct().toList();
    }

    /**
     * The filters an initializer adds: {@code addFilter(name, filter)}, with a filter object, class or class name;
     * mapped by {@code addMappingForUrlPatterns(types, isMatchAfter, patterns..)}, after every filter mapped before
     * it when {@code isMatchAfter} (Spring Security's among them), or by servlet names (any request, as AuthTracer
     * reads them).
     */
    private void initialized(Resolved initializer, int order) {
        for (JavaSootMethod method : initializer.code() == null ? List.<JavaSootMethod>of()
                : initializer.code().methods()) {
            Map<Local, Resolved> added = new LinkedHashMap<>();
            Map<Local, CodeRef> sites = new HashMap<>();
            Map<Local, List<String>> urls = new HashMap<>();
            Map<Local, Integer> orders = new HashMap<>();
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty() || invoke.get().getArgCount() < 2) {
                    continue;
                }
                String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                String name = invoke.get().getMethodSignature().getName();
                if (owner.equals(SERVLET_CONTEXT) && name.equals("addFilter")
                        && stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof Local registration) {
                    Value filter = invoke.get().getArg(1);
                    Optional<String> named = GroovyCalls.className(filter).or(() -> HttpClientEgress.constant(method,
                            filter));
                    added.put(registration, named.map(found -> typed(context.type(found), Kind.FILTER, false))
                            .orElseGet(() -> resolve(method, filter, Kind.FILTER)));
                    sites.put(registration, MethodNames.codeRef(method.getSignature(), stmt));
                }
                else if (owner.startsWith(FILTER_REGISTRATION_API) && invoke.get() instanceof AbstractInstanceInvokeExpr
                        call && call.getBase() instanceof Local registration && added.containsKey(registration)) {
                    if (name.equals("addMappingForUrlPatterns")) {
                        List<String> patterns = Locals.strings(method.getBody(), invoke.get().getArg(2));
                        urls.merge(registration, patterns, (first, more) -> {
                            List<String> all = new ArrayList<>(first);
                            all.addAll(more);
                            return all;
                        });
                        if (invoke.get().getArg(1) instanceof IntConstant after && after.getValue() != 0) {
                            orders.put(registration, Ordered.LOWEST_PRECEDENCE);
                        }
                    }
                    else {
                        // Servlet names, or patterns AuthTracer can't read: any request.
                        urls.put(registration, null);
                    }
                }
            }
            added.forEach((registration, filter) -> {
                CodeRef site = sites.get(registration);
                int at = orders.getOrDefault(registration, order);
                filter.pass(site).ifPresentOrElse(pass -> registered.add(new Registered(pass, at,
                        urls.containsKey(registration) ? urls.get(registration) : List.of())),
                        () -> library(filter, at < securityOrder, site));
            });
        }
    }

    // Spring MVC's interceptors.

    /**
     * {@code WebMvcConfigurer#addInterceptors}: {@code registry.addInterceptor(..)} (or
     * {@code addWebRequestInterceptor}), then {@code addPathPatterns}, {@code excludePathPatterns} and {@code order}
     * on what it returns.
     */
    private void readInterceptors() {
        for (JavaSootClass cls : context.applicationClasses()) {
            if (cls.isInterface() || !beans.isBean(cls.getType()) || !SpringBeans.assignable(context, cls.getType(),
                    Set.of(WEB_MVC_CONFIGURER))) {
                continue;
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (method.getName().equals("addInterceptors") && method.getParameterCount() == 1
                        && method.hasBody()) {
                    interceptors(method);
                }
            }
        }
    }

    private void interceptors(JavaSootMethod method) {
        Map<Local, Integer> registrations = new HashMap<>();
        List<Pass> found = new ArrayList<>();
        List<List<String>> includes = new ArrayList<>();
        List<List<String>> excludes = new ArrayList<>();
        List<Integer> orders = new ArrayList<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty() || invoke.get().getArgCount() != 1) {
                continue;
            }
            String declaring = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
            String name = invoke.get().getMethodSignature().getName();
            Integer index = null;
            if (declaring.equals(INTERCEPTOR_REGISTRY)
                    && (name.equals("addInterceptor") || name.equals("addWebRequestInterceptor"))) {
                index = found.size();
                found.add(resolve(method, invoke.get().getArg(0), Kind.INTERCEPTOR)
                        .pass(MethodNames.codeRef(method.getSignature(), stmt)).orElse(null));
                includes.add(new ArrayList<>());
                excludes.add(new ArrayList<>());
                orders.add(0);
            }
            else if (declaring.equals(INTERCEPTOR_REGISTRATION) && invoke.get() instanceof AbstractInstanceInvokeExpr call
                    && registrations.containsKey(call.getBase())) {
                index = registrations.get(call.getBase());
                Immediate argument = invoke.get().getArg(0);
                switch (name) {
                    case "addPathPatterns" -> add(includes, index, ServletEndpoints.mappings(method, argument));
                    case "excludePathPatterns" -> add(excludes, index, ServletEndpoints.mappings(method, argument));
                    case "order" -> {
                        if (argument instanceof IntConstant constant) {
                            orders.set(index, constant.getValue());
                        }
                    }
                    default -> {
                    }
                }
            }
            if (index != null && stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof Local result) {
                registrations.put(result, index);
            }
        }
        for (int i = 0; i < found.size(); i++) {
            Pass pass = found.get(i);
            if (pass == null) {
                continue;
            }
            interceptors.add(new Interceptor(pass.code() == null ? pass : part(pass, "preHandle"),
                    part(pass, "postHandle"), part(pass, "afterCompletion"), orders.get(i), includes.get(i),
                    excludes.get(i)));
        }
    }

    /**
     * {@code MappedInterceptor} beans (Spring Framework 7.0.9): every handler mapping detects them
     * ({@code AbstractHandlerMapping#detectMappedInterceptors}, in bean order) and runs them before the interceptors
     * it is given, the {@code InterceptorRegistry}'s among them. {@code new MappedInterceptor(includes[, excludes
     * [, includeMethods, excludeMethods]], interceptor[, parser])}: no includes is every path; HTTP methods, when
     * given, aren't read, so the interceptor may run for any request it covers.
     */
    private void readMappedInterceptors() {
        for (JavaSootMethod bean : beanMethods()) {
            if (!(bean.getReturnType() instanceof ClassType type)
                    || !SpringBeans.assignable(context, type, Set.of(MAPPED_INTERCEPTOR))) {
                continue;
            }
            for (Stmt stmt : bean.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty() || !invoke.get().getMethodSignature().getName().equals("<init>")
                        || !invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName()
                                .equals(MAPPED_INTERCEPTOR)) {
                    continue;
                }
                List<String> types = invoke.get().getMethodSignature().getParameterTypes().stream()
                        .map(Object::toString).toList();
                int target = types.indexOf("org.springframework.web.servlet.HandlerInterceptor") >= 0
                        ? types.indexOf("org.springframework.web.servlet.HandlerInterceptor")
                        : types.indexOf("org.springframework.web.context.request.WebRequestInterceptor");
                Pass pass = resolve(bean, invoke.get().getArg(target), Kind.INTERCEPTOR)
                        .pass(MethodNames.codeRef(bean.getSignature(), stmt)).orElse(null);
                if (pass == null) {
                    continue;
                }
                List<String> include = patterns(bean, invoke.get().getArg(0));
                List<String> exclude = target > 1 ? patterns(bean, invoke.get().getArg(1)) : List.of();
                if (target > 3 && !(invoke.get().getArg(2) instanceof NullConstant
                        && invoke.get().getArg(3) instanceof NullConstant)) {
                    // Unread excludes: a request its includes take may pass it.
                    exclude = null;
                }
                mapped.add(new Interceptor(pass.code() == null ? pass : part(pass, "preHandle"),
                        part(pass, "postHandle"), part(pass, "afterCompletion"), 0, include, exclude));
            }
        }
    }

    /**
     * A {@code MappedInterceptor}'s patterns: {@code null} is none, which for its includes is every path; patterns
     * AuthTracer can't read are {@code null}.
     */
    private static List<String> patterns(JavaSootMethod method, Immediate value) {
        return value instanceof NullConstant ? List.of() : ServletEndpoints.mappings(method, value).orElse(null);
    }

    /**
     * Patterns read into a registration's; once one can't be read, {@code null}.
     */
    private static void add(List<List<String>> patterns, int index, Optional<List<String>> read) {
        if (patterns.get(index) != null) {
            patterns.set(index, read.map(found -> {
                List<String> all = new ArrayList<>(patterns.get(index));
                all.addAll(found);
                return all;
            }).orElse(null));
        }
    }

    /**
     * An interceptor's {@code preHandle}, {@code postHandle} or {@code afterCompletion}; {@code null} when it doesn't
     * override it.
     */
    private static Pass part(Pass interceptor, String name) {
        List<JavaSootMethod> methods = interceptor.code() == null ? List.of() : interceptor.code().methods().stream()
                .filter(method -> method.getName().equals(name)).toList();
        return methods.isEmpty() ? null : new Pass(interceptor.code().with(methods), null, interceptor.site(),
                interceptor.bean());
    }

    /**
     * {@code MappedInterceptor#matches}, on the path within the DispatcherServlet: no include pattern is every path,
     * an exclusion wins. Patterns AuthTracer can't read may take in or leave out any request.
     */
    private static Coverage covers(Interceptor interceptor, Ingress request) {
        boolean excluded = interceptor.exclude() != null && HttpSecurityRules.Matcher.paths(null,
                interceptor.exclude()).matches(request.httpMethod(), request.route());
        if (excluded) {
            return Coverage.NO;
        }
        if (interceptor.include() == null) {
            return Coverage.MAYBE;
        }
        boolean included = HttpSecurityRules.Matcher.paths(null, interceptor.include().isEmpty() ? List.of("/**")
                : interceptor.include()).matches(request.httpMethod(), request.route());
        return !included ? Coverage.NO : interceptor.exclude() == null ? Coverage.MAYBE : Coverage.YES;
    }

    // What a filter or interceptor value is.

    /**
     * The filter a bean method returns: the bean.
     */
    private Resolved beanReturned(JavaSootMethod method, Kind kind) {
        return returned(method, kind, 0).asBean();
    }

    /**
     * What a value passed as a filter or interceptor is: an object made here, an injected bean, a bean method's or a
     * factory's result, or a lambda.
     */
    private Resolved resolve(JavaSootMethod method, Value value, Kind kind) {
        return resolve(method, value, kind, 0);
    }

    private Resolved resolve(JavaSootMethod method, Value value, Kind kind, int depth) {
        if (value instanceof Local local && depth < 4) {
            List<Value> definitions = Locals.definitions(method.getBody(), local);
            if (definitions.size() > 1) {
                // Picked on branches (cond ? new A() : new B()): any of them may be the one.
                return oneOf(definitions.stream().map(definition -> resolve(method, definition, kind, depth + 1))
                        .distinct().toList());
            }
        }
        Value definition = value instanceof Local local ? Locals.definition(method.getBody(), local).orElse(value)
                : value;
        if (definition instanceof JCastExpr cast && depth < 4) {
            return resolve(method, cast.getOp(), kind, depth + 1);
        }
        if (definition instanceof JNewExpr created) {
            return typed(created.getType(), kind, false);
        }
        if (definition instanceof JParameterRef parameter
                && method.getParameterType(parameter.getIndex()) instanceof ClassType type) {
            return typed(type, kind, true);
        }
        if (definition instanceof JFieldRef field && field.getFieldSignature().getType() instanceof ClassType type) {
            return typed(type, kind, true);
        }
        Optional<JavaSootMethod> lambda = definition instanceof JDynamicInvokeExpr dynamic
                && GroovyCalls.of(dynamic).isEmpty() ? lambda(dynamic) : Optional.empty();
        if (lambda.isPresent()) {
            return new Resolved(new Code(MethodNames.key(lambda.get().getSignature()), null, List.of(lambda.get()),
                    false, false), null, null, false);
        }
        if (definition instanceof AbstractInvokeExpr call && depth < 4) {
            List<JavaSootMethod> targets = List.copyOf(calls.targets(call));
            if (targets.size() == 1 && targets.getFirst().hasBody()) {
                // A bean method of the same configuration, or a factory method: what it returns.
                Resolved returned = returned(targets.getFirst(), kind, depth + 1);
                return context.hasAnnotation(targets.getFirst(), SpringNames.BEAN) ? returned.asBean() : returned;
            }
            if (call.getMethodSignature().getType() instanceof ClassType type) {
                Resolved typed = typed(type, kind, false);
                return typed.unresolved() == null ? typed : new Resolved(null, "the "
                        + MethodNames.simpleName(type.getFullyQualifiedName()) + " "
                        + call.getMethodSignature().getDeclClassType().getClassName() + "#"
                        + call.getMethodSignature().getName() + " returns", null, false);
            }
        }
        return value.getType() instanceof ClassType type ? typed(type, kind, false) : Resolved.LIBRARY;
    }

    /**
     * The application method a lambda or method reference implements.
     */
    private Optional<JavaSootMethod> lambda(JDynamicInvokeExpr dynamic) {
        for (Value argument : dynamic.getBootstrapArgs()) {
            if (argument instanceof MethodHandle handle && handle.isMethodRef()
                    && handle.getReferenceSignature() instanceof MethodSignature signature
                    && context.isApplication(signature.getDeclClassType())) {
                Optional<JavaSootMethod> found = context.findMethod(signature).filter(JavaSootMethod::hasBody);
                if (found.isPresent()) {
                    return found;
                }
            }
        }
        return Optional.empty();
    }

    private Resolved returned(JavaSootMethod method, Kind kind, int depth) {
        List<Resolved> returned = method.getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                .map(stmt -> resolve(method, ((JReturnStmt) stmt).getOp(), kind, depth)).distinct().toList();
        return returned.isEmpty() ? Resolved.LIBRARY : oneOf(returned);
    }

    /**
     * What a value picked in code is: the one every branch gives, else unresolved, naming them.
     */
    private static Resolved oneOf(List<Resolved> each) {
        if (each.size() == 1) {
            return each.getFirst();
        }
        List<String> names = each.stream().map(resolved -> resolved.code() != null ? resolved.code().name()
                : resolved.unresolved() != null ? resolved.unresolved() : "a library class").toList();
        return new Resolved(null, "one of " + String.join(", ", names) + ", picked in code", null,
                each.stream().allMatch(Resolved::bean));
    }

    /**
     * A value of a declared type: an application class's code; for an interface or abstract type, the one
     * application class (a bean, when the value is one) that may be it, else unresolved; a library class runs
     * library code only.
     */
    private Resolved typed(ClassType type, Kind kind, boolean bean) {
        Optional<JavaSootClass> cls = context.findClass(type);
        boolean concrete = cls.isPresent() && !cls.get().isInterface() && !cls.get().isAbstract();
        if (concrete && context.isApplication(type)) {
            return new Resolved(code(type, kind), null, type, bean);
        }
        if (concrete) {
            // Library code only; its class places it (addFilter) and may make it a way in.
            return new Resolved(null, null, type, bean);
        }
        List<ClassType> candidates = context.subtypesOf(type).stream().filter(subtype -> context.findClass(subtype)
                .filter(found -> !found.isInterface() && !found.isAbstract()).isPresent())
                .filter(subtype -> !bean || beans.isBean(subtype)).toList();
        if (candidates.size() == 1) {
            return new Resolved(code(candidates.getFirst(), kind), null, candidates.getFirst(), bean);
        }
        return new Resolved(null, "a " + MethodNames.simpleName(type.getFullyQualifiedName())
                + (candidates.isEmpty() || candidates.size() > 3 ? "" : " that may be any of "
                        + String.join(", ", candidates.stream().map(ClassType::getClassName).toList())), null, bean);
    }

    /**
     * What Spring calls on a filter or interceptor of an application class: a {@code OncePerRequestFilter}'s
     * {@code doFilterInternal} (conditional when it overrides {@code shouldNotFilter}), a filter's {@code doFilter} or
     * a {@code WebFilter}'s {@code filter}; an interceptor's {@code preHandle}, {@code postHandle} and
     * {@code afterCompletion}. A class that extends a library filter without these runs the library's, which calls
     * the methods the class overrides for some requests.
     */
    private Code code(ClassType type, Kind kind) {
        String name = type.getClassName();
        boolean once = context.superClassesOf(type).stream()
                .anyMatch(superclass -> superclass.getFullyQualifiedName().equals(ONCE_PER_REQUEST));
        if (kind == Kind.INTERCEPTOR) {
            List<JavaSootMethod> methods = new ArrayList<>();
            for (String method : List.of("preHandle", "postHandle", "afterCompletion")) {
                own(type, method).ifPresent(methods::add);
            }
            return new Code(name, type, methods, false, false);
        }
        if (kind == Kind.INITIALIZER) {
            return new Code(name, type, own(type, "onStartup").stream().toList(), false, false);
        }
        Optional<JavaSootMethod> entry = kind == Kind.WEB_FILTER ? own(type, "filter")
                : own(type, "doFilterInternal").or(() -> own(type, "doFilter"));
        if (entry.isPresent()) {
            boolean skips = entry.get().getName().equals("doFilterInternal") && own(type, "shouldNotFilter").isPresent();
            return new Code(name, type, List.of(entry.get()), skips, once);
        }
        return new Code(name, type, hooks(type), true, once);
    }

    /**
     * The class's (or an application superclass's) method of that name, nearest first.
     */
    private Optional<JavaSootMethod> own(ClassType type, String name) {
        List<ClassType> chain = new ArrayList<>(List.of(type));
        chain.addAll(context.superClassesOf(type));
        for (ClassType candidate : chain) {
            if (!context.isApplication(candidate)) {
                break;
            }
            Optional<JavaSootMethod> found = context.findClass(candidate).stream()
                    .flatMap(cls -> cls.getMethods().stream())
                    .filter(method -> method.getName().equals(name) && method.hasBody() && !method.isStatic()
                            && !MethodModifier.isBridge(method.getModifiers())
                            && !MethodModifier.isSynthetic(method.getModifiers()))
                    .findFirst();
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    /**
     * The methods the class (or an application superclass) overrides of the library class it extends.
     */
    private List<JavaSootMethod> hooks(ClassType type) {
        List<ClassType> chain = new ArrayList<>(List.of(type));
        chain.addAll(context.superClassesOf(type));
        List<JavaSootClass> library = chain.stream().filter(candidate -> !context.isApplication(candidate))
                .flatMap(candidate -> context.findClass(candidate).stream()).toList();
        Map<String, JavaSootMethod> hooks = new LinkedHashMap<>();
        for (ClassType candidate : chain) {
            if (!context.isApplication(candidate)) {
                break;
            }
            for (JavaSootMethod method : context.findClass(candidate).map(JavaSootClass::getMethods)
                    .orElse(Set.of())) {
                boolean overrides = method.hasBody() && !method.isStatic() && !method.isPrivate()
                        && !method.getName().startsWith("<") && !MethodModifier.isBridge(method.getModifiers())
                        && !MethodModifier.isSynthetic(method.getModifiers())
                        && library.stream().anyMatch(cls -> cls.getMethod(method.getSignature().getSubSignature())
                                .filter(inherited -> !inherited.isPrivate() && !inherited.isStatic()).isPresent());
                if (overrides) {
                    hooks.putIfAbsent(method.getSignature().getSubSignature().toString(), method);
                }
            }
        }
        return List.copyOf(hooks.values());
    }

    private static Map<String, Integer> servletOrders() {
        String authentication = WEB + "authentication.";
        String oauth2Client = "org.springframework.security.oauth2.client.web.";
        String saml2 = "org.springframework.security.saml2.provider.service.web.";
        List<String> order = new ArrayList<>(List.of(WEB + "session.DisableEncodeUrlFilter",
                WEB + "session.ForceEagerSessionCreationFilter", WEB + "access.channel.ChannelProcessingFilter",
                WEB + "transport.HttpsRedirectFilter", "", WEB + "context.request.async.WebAsyncManagerIntegrationFilter",
                WEB + "context.SecurityContextHolderFilter", WEB + "context.SecurityContextPersistenceFilter",
                WEB + "header.HeaderWriterFilter", "org.springframework.web.filter.CorsFilter", WEB + "csrf.CsrfFilter",
                authentication + "logout.LogoutFilter", oauth2Client + "OAuth2AuthorizationRequestRedirectFilter",
                saml2 + "Saml2WebSsoAuthenticationRequestFilter", authentication + "ott.GenerateOneTimeTokenFilter",
                authentication + "preauth.x509.X509AuthenticationFilter",
                authentication + "preauth.AbstractPreAuthenticatedProcessingFilter",
                "org.springframework.security.cas.web.CasAuthenticationFilter",
                oauth2Client + "OAuth2LoginAuthenticationFilter", saml2 + "authentication.Saml2WebSsoAuthenticationFilter",
                authentication + "UsernamePasswordAuthenticationFilter",
                authentication + "ott.OneTimeTokenAuthenticationFilter", "",
                authentication + "ui.DefaultResourcesFilter", authentication + "ui.DefaultLoginPageGeneratingFilter",
                authentication + "ui.DefaultLogoutPageGeneratingFilter",
                authentication + "ui.DefaultOneTimeTokenSubmitPageGeneratingFilter",
                WEB + "session.ConcurrentSessionFilter", authentication + "www.DigestAuthenticationFilter",
                "org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter",
                authentication + "www.BasicAuthenticationFilter", authentication + "AuthenticationFilter",
                WEB + "savedrequest.RequestCacheAwareFilter", WEB + "servletapi.SecurityContextHolderAwareRequestFilter",
                WEB + "jaasapi.JaasApiIntegrationFilter", authentication + "rememberme.RememberMeAuthenticationFilter",
                authentication + "AnonymousAuthenticationFilter", oauth2Client + "OAuth2AuthorizationCodeGrantFilter",
                WEB + "session.SessionManagementFilter", WEB + "access.ExceptionTranslationFilter",
                WEB + "access.intercept.FilterSecurityInterceptor", AUTHORIZATION_FILTER,
                authentication + "switchuser.SwitchUserFilter"));
        Map<String, Integer> orders = new HashMap<>();
        for (int i = 0; i < order.size(); i++) {
            if (!order.get(i).isEmpty()) {
                orders.put(order.get(i), (i + 1) * 100);
            }
        }
        return Map.copyOf(orders);
    }
}
