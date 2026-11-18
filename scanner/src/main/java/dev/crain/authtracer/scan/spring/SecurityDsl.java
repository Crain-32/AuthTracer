package dev.crain.authtracer.scan.spring;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Might;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.ClassFileMetadata.GenericType;
import dev.crain.authtracer.scan.GroovyCalls;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Matcher;
import dev.crain.authtracer.scan.spring.HttpSecurityRules.Rule;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JInstanceFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JIdentityStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Interprets Spring Security's configuration DSL from bytecode: the Java lambda DSL, the Kotlin DSL
 * ({@code http { authorizeHttpRequests { authorize(..) } }}) and closures in dynamic Groovy. Each local holds what it
 * stands for (the {@code HttpSecurity}, a rule registry, a matcher, a manager), so a call is read by what it is made
 * on, whichever language compiled it.
 */
@Supports(Feature.REQUEST_RULES)
final class SecurityDsl {

    private static final String HTTP_METHOD = "org.springframework.http.HttpMethod";
    private static final String WEB_EXPRESSION_MANAGER =
            "org.springframework.security.web.access.expression.WebExpressionAuthorizationManager";

    /**
     * Managers created with {@code new} or static factories don't see {@code GrantedAuthorityDefaults}.
     */
    static final SpelRequirements DEFAULT_ROLES = new SpelRequirements("ROLE_");
    private static final String AUTHORIZATION_MANAGER = "org.springframework.security.authorization.AuthorizationManager";
    private static final String AUTHORIZATION_MANAGER_FACTORY =
            "org.springframework.security.authorization.AuthorizationManagerFactory";
    private static final String AUTHORIZATION_PACKAGE = "org.springframework.security.authorization.";
    private static final String AUTHORIZATION_DECISION = AUTHORIZATION_PACKAGE + "AuthorizationDecision";
    private static final String SERVER_HTTP_SECURITY = "org.springframework.security.config.web.server.ServerHttpSecurity";
    private static final String SERVER_MATCHERS = "org.springframework.security.web.server.util.matcher.";
    private static final String REACTIVE_PATH_REQUEST =
            "org.springframework.boot.security.autoconfigure.web.reactive.PathRequest";
    private static final String GROOVY_CLOSURE = "groovy.lang.Closure";
    static final String GRPC_SECURITY = "org.springframework.grpc.server.security.GrpcSecurity";
    private static final String ABSTRACT_HTTP_CONFIGURER =
            "org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer";
    /**
     * Library configurers whose {@code init} and {@code configure} add no rules, filters or matchers (javap): Spring
     * Boot 4.1.1's gRPC server only turns CSRF protection off for gRPC requests.
     */
    private static final Set<String> CONFIGURERS_WITHOUT_RULES = Set.of(
            "org.springframework.boot.grpc.server.autoconfigure.security.GrpcDisableCsrfHttpConfigurer");
    /**
     * The configurers each library jar's {@code META-INF/spring.factories} lists, by the jar and its size and time.
     */
    private static final Map<String, List<String>> LIBRARY_FACTORIES = new ConcurrentHashMap<>();
    private static final Set<String> HTTP_BUILDERS = Set.of(SpringNames.HTTP_SECURITY,
            "org.springframework.security.config.annotation.web.HttpSecurityBuilder",
            "org.springframework.security.config.annotation.SecurityBuilder");
    private static final String GRPC_REQUEST =
            "org.springframework.boot.grpc.server.autoconfigure.security.web.servlet.GrpcRequest";

    /**
     * Java varargs methods of the DSL, which dynamic Groovy calls with separate arguments.
     */
    private static final Set<String> GROOVY_VARARGS = Set.of("requestMatchers", "pathMatchers", "matchers",
            "securityMatcher", "anyOf", "allOf", "dispatcherTypeMatchers");

    /**
     * The Kotlin DSL's entry points, {@code http { }}.
     */
    private static final Set<String> KOTLIN_DSL_ENTRY = Set.of(
            "org.springframework.security.config.annotation.web.HttpSecurityDslKt",
            "org.springframework.security.config.web.server.ServerHttpSecurityDslKt");
    private static final String REGEX_MATCHER = "org.springframework.security.web.util.matcher.RegexRequestMatcher";
    private static final String ENDPOINT_REQUEST =
            "org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest";
    private static final String REACTIVE_ENDPOINT_REQUEST =
            "org.springframework.boot.security.autoconfigure.actuate.web.reactive.EndpointRequest";
    /**
     * A class literal among a call's arguments, e.g. {@code EndpointRequest.to(HealthEndpoint.class)}.
     */
    private static final String CLASS_LITERAL = "class:";
    private static final String PATH_PATTERN_MATCHER =
            "org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher";
    static final String MATCHER_BUILDER = PATH_PATTERN_MATCHER + "$Builder";
    private static final String PATH_REQUEST = "org.springframework.boot.security.autoconfigure.web.servlet.PathRequest";
    private static final String STATIC_RESOURCE_LOCATION =
            "org.springframework.boot.security.autoconfigure.web.StaticResourceLocation";
    private static final String DISPATCHER_TYPE = "jakarta.servlet.DispatcherType";
    private static final String AUTHORIZATION_SERVER_CONFIGURER = "org.springframework.security.config.annotation.web"
            + ".configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer";
    static final String OBJECT_POST_PROCESSOR = "org.springframework.security.config.ObjectPostProcessor";
    private static final String AUTHORIZATION_FILTER =
            "org.springframework.security.web.access.intercept.AuthorizationFilter";
    private static final GenericType FILTER_POST_PROCESSOR = new GenericType(OBJECT_POST_PROCESSOR,
            List.of(new GenericType(AUTHORIZATION_FILTER, List.of())));
    private static final Set<String> DISPATCH_SETTERS = Set.of("setObserveOncePerRequest", "setFilterErrorDispatch",
            "setFilterAsyncDispatch", "setAuthorizationEventPublisher");
    private static final String DISPATCHER_MATCHER =
            "org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher";

    /**
     * Spring Boot 4.1.1's {@code StaticResourceLocation} patterns, relative to the DispatcherServlet path.
     */
    private static final Map<String, List<String>> STATIC_RESOURCES = new LinkedHashMap<>();

    static {
        STATIC_RESOURCES.put("CSS", List.of("/css/**"));
        STATIC_RESOURCES.put("JAVA_SCRIPT", List.of("/js/**"));
        STATIC_RESOURCES.put("IMAGES", List.of("/images/**"));
        STATIC_RESOURCES.put("WEB_JARS", List.of("/webjars/**"));
        STATIC_RESOURCES.put("FAVICON", List.of("/favicon.*", "/icons/icon-*"));
        STATIC_RESOURCES.put("FONTS", List.of("/fonts/**"));
    }

    private sealed interface DslValue {
    }

    private record Registry() implements DslValue {
    }

    /**
     * @param not {@code not()} came first: the rule's manager is negated (7.1.1 {@code AuthorizedUrl#access})
     */
    private record AuthorizedUrl(Matcher matcher, boolean not) implements DslValue {
    }

    /**
     * {@code hasVariable(name)}, whose {@code equalTo(..)} compares a path variable with something of the caller's.
     */
    private record UrlVariable(AuthorizedUrl url, String variable) implements DslValue {
    }

    /**
     * The managers whose arguments are authorities, roles or addresses: unread when an argument isn't a constant.
     */
    private static final Set<String> AUTHORITY_METHODS = Set.of("hasRole", "hasAnyRole", "hasAllRoles",
            "hasAuthority", "hasAnyAuthority", "hasAllAuthorities", "hasIpAddress");
    private static final Set<String> CUSTOMIZERS = Set.of("org.springframework.security.config.Customizer",
            "org.springframework.security.config.ThrowingCustomizer");
    /**
     * How deep helper methods are followed: {@code configure(http)} calling {@code rules(http)}.
     */
    private static final int MAX_FOLLOWED = 3;

    /**
     * Spring gRPC's {@code GrpcSecurity} (decision 0032), its {@code authorizeRequests} configurer, and a call
     * matcher it returns, negated by {@code not()}.
     */
    private record Grpc() implements DslValue {
    }

    private record GrpcRegistry() implements DslValue {
    }

    private record GrpcCall(Matcher matcher, boolean not) implements DslValue {
    }

    /**
     * Boot's {@code GrpcRequest.toAnyService()} (decision 0032): {@code /<service>/**} for every gRPC service the
     * application serves through the servlet container, but the {@code excluding(..)} ones.
     */
    private record GrpcServlet(Set<String> excluded) implements DslValue {
    }

    private record Http() implements DslValue {
    }

    private record Web() implements DslValue {
    }

    private record IgnoredRequests() implements DslValue {
    }

    /**
     * An array: strings, {@code AuthorizationManager}s for {@code anyOf}/{@code allOf}, or {@code RequestMatcher}s;
     * {@code unknown} holds elements that are none of these.
     */
    private record Strings(List<String> values, List<Requirement> managers, List<Matcher> matchers,
            List<String> unknown) implements DslValue {

        Strings(List<String> values) {
            this(values, new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
        }
    }

    /**
     * A {@code RequestMatcher} built in code: {@code RegexRequestMatcher.regexMatcher(..)},
     * {@code PathPatternRequestMatcher.pathPattern(..)}, a builder's {@code matcher(..)}, {@code PathRequest}.
     */
    private record MatcherValue(Matcher matcher) implements DslValue {
    }

    /**
     * A {@code PathPatternRequestMatcher.Builder}; {@code basePath} prefixes the patterns it builds.
     */
    private record MatcherBuilder(String basePath) implements DslValue {

        String prefixed(String pattern) {
            return basePath == null || basePath.equals("/") ? pattern : basePath + pattern;
        }
    }

    /**
     * Spring Boot's {@code PathRequest.toStaticResources()}, and the locations it was narrowed to.
     */
    private record StaticResources(List<String> locations) implements DslValue {
    }

    /**
     * The {@code RequestMatcherConfigurer} that {@code securityMatchers(..)} hands its lambda.
     */
    private record SecurityMatchers() implements DslValue {
    }

    /**
     * The {@code OAuth2AuthorizationServerConfigurer} that {@code oauth2AuthorizationServer(..)} hands its lambda.
     */
    private record AuthorizationServer() implements DslValue {
    }

    /**
     * {@code WebExpressionAuthorizationManager.withDefaults()}: its handler has the {@code ROLE_} prefix and no
     * RoleHierarchy, like {@code new WebExpressionAuthorizationManager(..)}.
     */
    private record WebExpressionBuilder() implements DslValue {
    }

    /**
     * The Kotlin DSL's {@code authorizeHttpRequests { }} ({@code AuthorizeHttpRequestsDsl}) or
     * {@code authorizeExchange { }} ({@code AuthorizeExchangeDsl}) receiver.
     */
    private record KotlinRules() implements DslValue {
    }

    /**
     * A manager the Kotlin DSL builds ({@code hasRole("X")}, {@code permitAll}): the same factory as the Java DSL,
     * so the same prefix and RoleHierarchy.
     */
    private record DslManager(Requirement requirement) implements DslValue {
    }

    /**
     * An argument a Kotlin call leaves out, so its default applies.
     */
    private record Defaulted() implements DslValue {
    }

    /**
     * An {@code AuthorizationManager} built from Spring Security's static factories.
     *
     * @param hierarchy whether {@code setRoleHierarchy(..)} gave it the RoleHierarchy, which the factories don't
     */
    private record Manager(Requirement requirement, boolean hierarchy) implements DslValue {

        Manager(Requirement requirement) {
            this(requirement, false);
        }
    }

    /**
     * Decision 0037: a multi-factor builder in progress: {@code AuthorizationManagerFactories.multiFactor()} (a
     * factory), {@code AllRequiredFactorsAuthorizationManager.builder()} (a manager) or a {@code RequiredFactor}.
     */
    private static final class FactorsBuilder implements DslValue {
        enum Kind {
            FACTORY, MANAGER, FACTOR
        }

        final Kind kind;
        final MultiFactor.Factors factors = new MultiFactor.Factors();

        FactorsBuilder(Kind kind) {
            this.kind = kind;
        }
    }

    /**
     * An {@code AuthorizationManagerFactory} built in place, whose managers also need {@code additional}.
     */
    private record FactoryValue(Requirement additional) implements DslValue {
    }

    /**
     * Decision 0041: Spring Boot's {@code EndpointRequest} matchers, on the Actuator endpoints that are exposed.
     *
     * @param ids the endpoints, {@code null} for any
     * @param links whether the base path's links page is included
     */
    private record EndpointMatcher(Set<String> ids, Set<String> excluded, boolean links, String method)
            implements DslValue {
    }

    /**
     * {@code ConditionalAuthorizationManager.when(..)} in progress (AUTHZ-05).
     */
    private static final class Conditional implements DslValue {
        Requirement whenTrue;
        Requirement whenFalse;
    }

    /**
     * HTTP-18: a {@code formLogin(..)} or {@code logout(..)} call, and what it sets on its configurer, in order. The
     * calls on one configurer, in a customizer and in the chain, add up: see {@link SecurityDsl#permitted}.
     */
    private record LoginUrls(boolean logout, int line, List<java.util.function.Consumer<LoginState>> calls)
            implements DslValue {

        LoginUrls(boolean logout, int line) {
            this(logout, line, new ArrayList<>());
        }
    }

    /**
     * A {@code formLogin(..)} or {@code logout(..)} configurer, and the URLs its {@code permitAll()} lets everyone
     * reach, ahead of every other rule (7.1.1 {@code PermitAllSupport}): the login page, the processing URL and the
     * failure URL, or the logout URL and the logout success URL. Unset URLs are {@code null}.
     */
    private static final class LoginState {
        final boolean logout;
        int line;
        String page;
        String processing;
        String failure;
        /**
         * {@code failureHandler(..)} or {@code failureForwardUrl(..)}: no failure URL, until a {@code failureUrl(..)}.
         */
        boolean noFailure;
        String logoutUrl;
        String logoutSuccess;
        /**
         * {@code logoutSuccessHandler(..)}: no logout success URL, until a {@code logoutSuccessUrl(..)}.
         */
        boolean noSuccess;
        Matcher logoutMatcher;
        boolean permitAll;

        LoginState(boolean logout) {
            this.logout = logout;
        }

        /**
         * Decision 0093: what {@code permitAll()} lets through. The login URLs and the logout success URL are exact,
         * query string included (7.1.1 {@code ExactUrlRequestMatcher}); the failure URL defaults to the login page's
         * {@code ?error}, the logout success URL to the form login page's {@code ?logout}
         * ({@code AbstractAuthenticationFilterConfigurer#updateAuthenticationDefaults}). The logout URL is
         * {@code LogoutConfigurer}'s own matcher: {@code POST}, or {@code GET}, {@code POST}, {@code PUT} and
         * {@code DELETE} once CSRF protection is off.
         *
         * @param loginPage the chain's form login page, {@code null} for the default
         */
        Matcher permitted(boolean csrfOff, String loginPage) {
            String login = Objects.requireNonNullElse(loginPage, "/login");
            if (!logout) {
                List<String> urls = new ArrayList<>(List.of(login, Objects.requireNonNullElse(processing, login)));
                if (!noFailure) {
                    urls.add(Objects.requireNonNullElse(failure, login + "?error"));
                }
                return Matcher.exactUrls(urls.stream().distinct().toList());
            }
            String url = Objects.requireNonNullElse(logoutUrl, "/logout");
            Matcher request = logoutMatcher != null ? logoutMatcher : Matcher.anyOf((csrfOff
                    ? List.of("GET", "POST", "PUT", "DELETE") : List.of("POST")).stream()
                    .map(method -> Matcher.paths(method, List.of(url))).toList(), List.of());
            return Matcher.anyOf(List.of(request, Matcher.exactUrls(noSuccess ? List.of()
                    : List.of(Objects.requireNonNullElse(logoutSuccess, login + "?logout")))), List.of());
        }
    }

    /**
     * A {@code csrf(..)} lambda's configurer: whether it calls {@code disable()}.
     */
    private static final class Csrf implements DslValue {
        boolean disabled;
    }

    /**
     * Decision 0093: the rules the {@code permitAll()} of a chain's {@code formLogin(..)} and {@code logout(..)} add,
     * from what configures that chain in the order Spring applies it (7.1.1 {@code HttpSecurityConfiguration}: the
     * library DSLs, the {@code Customizer<HttpSecurity>} beans, then the bean method). The calls on one configurer
     * add up; CSRF protection is on unless they turn it off.
     */
    static List<Rule> permitted(List<Interpretation> interpretations) {
        LoginState form = new LoginState(false);
        LoginState logout = new LoginState(true);
        boolean csrfOff = false;
        for (Interpretation interpretation : interpretations) {
            for (LoginUrls urls : interpretation.logins) {
                LoginState state = urls.logout() ? logout : form;
                state.line = urls.line();
                urls.calls().forEach(call -> call.accept(state));
            }
            for (boolean off : interpretation.csrfOff) {
                csrfOff = off;
            }
        }
        List<Rule> rules = new ArrayList<>();
        for (LoginState state : List.of(form, logout)) {
            if (state.permitAll) {
                rules.add(new Rule(state.permitted(csrfOff, form.page), Requirement.permitAll(), state.line));
            }
        }
        return rules;
    }

    private record Text(String value) implements DslValue {
    }

    /**
     * An int or boolean constant ({@code permitAll(false)} is 0).
     */
    private record Number(int value) implements DslValue {
    }

    private record HttpMethodValue(String name) implements DslValue {
    }

    /**
     * @param captured the values the lambda captures, which come first among its body's parameters
     */
    private record Lambda(MethodSignature method, List<DslValue> captured) implements DslValue {
    }

    private record NewObject(String type, String text) implements DslValue {
    }

    /**
     * A method reference to a library's method, e.g. {@code CorsUtils::isPreFlightRequest}.
     */
    private record MethodReference(MethodSignature method) implements DslValue {
    }

    /**
     * What a lambda's parameter is: the {@code HttpSecurity} (or {@code ServerHttpSecurity}, or the Kotlin
     * {@code HttpSecurityDsl}), the {@code authorizeHttpRequests} registry, the Kotlin {@code AuthorizeHttpRequestsDsl},
     * or the {@code WebSecurity} of a {@code WebSecurityCustomizer}.
     */
    enum Receiver {
        HTTP, REGISTRY, KOTLIN_RULES, WEB
    }

    /**
     * What interpreting a method found.
     */
    static final class Interpretation {
        /**
         * {@code securityMatcher(..)} replaces it; {@code securityMatchers(..)} sets it to the OR of everything
         * {@code configured} so far (Spring Security 7.1.1's {@code RequestMatcherConfigurer}).
         */
        Matcher securityMatcher;
        final List<Matcher> configured = new ArrayList<>();
        final List<Rule> rules = new ArrayList<>();
        final List<Rule> ignored = new ArrayList<>();
        /**
         * HTTP-18: the {@code formLogin(..)} and {@code logout(..)} configurers, whose {@code permitAll()} lets the
         * login and logout URLs through, ahead of every rule: see {@link SecurityDsl#permitted}.
         */
        final List<LoginUrls> logins = new ArrayList<>();
        /**
         * Decision 0093: each {@code csrf(..)}, whether it turns CSRF protection off
         * ({@code csrf(AbstractHttpConfigurer::disable)}) or on. It is on by default.
         */
        final List<Boolean> csrfOff = new ArrayList<>();
        /**
         * HTTP-16: rules from custom DSLs ({@code http.with(new Dsl(), ..)}), which their {@code init} adds when the
         * chain is built, after the bean method's own.
         */
        final List<Rule> deferred = new ArrayList<>();
        /**
         * Rules whose requirement AuthTracer couldn't read, kept as opaque requirements: the requests they match get
         * them, not a later rule.
         */
        final List<Unread> unread = new ArrayList<>();
        final List<Note> opaque = new ArrayList<>();
        boolean authorizes;
        /**
         * HTTP-19: {@code setFilterErrorDispatch(false)} on the {@code AuthorizationFilter}: error dispatches skip
         * the rules.
         */
        boolean errorDispatchUnchecked;

        /**
         * What a custom DSL's {@code init} or {@code configure} found besides its rules.
         */
        void absorb(Interpretation other) {
            logins.addAll(other.logins);
            csrfOff.addAll(other.csrfOff);
            opaque.addAll(other.opaque);
            authorizes |= other.authorizes;
            errorDispatchUnchecked |= other.errorDispatchUnchecked;
        }
    }

    /**
     * @param requirement the opaque requirement the rule was given, e.g. {@code hasRole(?)}
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    record Unread(Matcher matcher, String requirement) {
    }

    /**
     * Configuration AuthTracer can't read, for an OPAQUE_CONFIG finding: what it is and where.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    record Note(String message, CodeRef where) {
    }

    private final ScanContext context;
    private final SpelRequirements spel;
    /**
     * RX-01: on WebFlux, {@code hasRole} is {@code AuthorityReactiveAuthorizationManager.hasRole}: always
     * {@code ROLE_}, never a RoleHierarchy.
     */
    private final boolean reactive;
    private final MatcherBuilder requestMatcherBuilder;
    private final String servletPath;
    private final Set<String> grpcServices;
    private final List<Rule> kotlinDslBeanRules = new ArrayList<>();
    private boolean kotlinDslBeanAuthorizes;
    private final Set<MethodSignature> following = new HashSet<>();
    /**
     * The method whose configuration is being read (a lambda's is the method that declares it), for findings.
     */
    private MethodSignature configuring;

    /**
     * @param spel the role prefix the DSL's own managers use
     * @param basePath the {@code PathPatternRequestMatcher.Builder} bean's base path, {@code null} for none
     * @param servletPath the DispatcherServlet's path, which Boot's {@code PathRequest} patterns are relative to
     * @param grpcServices the gRPC services the application serves, which Boot's {@code GrpcRequest} matches
     */
    SecurityDsl(ScanContext context, SpelRequirements spel, boolean reactive, String basePath, String servletPath,
            Set<String> grpcServices) {
        this.context = context;
        this.grpcServices = grpcServices;
        this.spel = spel;
        this.reactive = reactive;
        this.requestMatcherBuilder = new MatcherBuilder(basePath);
        this.servletPath = servletPath;
    }

    /**
     * HTTP-20: rules from Kotlin DSL beans, which every chain configured with {@code http { }} starts with.
     */
    void startKotlinChainsWith(List<Rule> rules, boolean authorizes) {
        kotlinDslBeanRules.addAll(rules);
        kotlinDslBeanAuthorizes |= authorizes;
    }

    /**
     * A {@code SecurityFilterChain} (or {@code SecurityWebFilterChain}) bean method, with its {@code HttpSecurity},
     * {@code PathPatternRequestMatcher.Builder} and {@code WebExpressionAuthorizationManager.Builder} parameters bound.
     */
    Interpretation chain(JavaSootMethod beanMethod) {
        Map<Integer, DslValue> parameters = new HashMap<>();
        for (int i = 0; i < beanMethod.getParameterCount(); i++) {
            if (beanMethod.getParameterType(i) instanceof ClassType type) {
                switch (type.getFullyQualifiedName()) {
                    case SpringNames.HTTP_SECURITY, SERVER_HTTP_SECURITY -> parameters.put(i, new Http());
                    case MATCHER_BUILDER -> parameters.put(i, requestMatcherBuilder);
                    case WEB_EXPRESSION_MANAGER + "$Builder" -> parameters.put(i, new WebExpressionBuilder());
                    case AUTHORIZATION_MANAGER, AUTHORIZATION_MANAGER_FACTORY -> {
                        DslValue bean = managerBean(beanMethod, i, type.getFullyQualifiedName());
                        if (bean == null) {
                            bean = injectedManager(type, beanMethod.getBody().getParameterLocal(i).getName());
                        }
                        if (bean != null) {
                            parameters.put(i, bean);
                        }
                    }
                    default -> {
                        DslValue bean = injectedManager(type, beanMethod.getBody().getParameterLocal(i).getName());
                        if (bean != null) {
                            parameters.put(i, bean);
                        }
                    }
                }
            }
        }
        Interpretation result = new Interpretation();
        root(beanMethod, parameters, result);
        return result;
    }

    /**
     * Decision 0064 (AUTHZ-01, RX-02): a custom manager handed to the chain method or held in a field, by its type or
     * the one bean of a manager type; {@code null} when it isn't one.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    private DslValue injectedManager(ClassType type, String name) {
        return DecisionCode.of(context).injected(type, name, "access(" + MethodNames.simpleName(
                type.getFullyQualifiedName()) + ")").map(Manager::new).orElse(null);
    }

    /**
     * Decision 0064: a manager the code creates or writes as a lambda, as what decides it.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    private Optional<Requirement> customManager(DslValue value) {
        if (value instanceof NewObject created && !created.type().equals(WEB_EXPRESSION_MANAGER)) {
            return DecisionCode.of(context).created(context.type(created.type()), "access("
                    + MethodNames.simpleName(created.type()) + ")");
        }
        if (value instanceof Lambda lambda && DecisionCode.isManagerLambda(lambda.method())) {
            return Optional.of(DecisionCode.of(context).lambda(lambda.method(), "access(" + lambda.method().getName()
                    + ")"));
        }
        return Optional.empty();
    }

    /**
     * An {@code AuthorizationManager} (or factory) bean a chain bean method is handed: the {@code @Bean} method of
     * that type with the parameter's name, or the only one, read for the manager it returns (decision 0037:
     * {@code multiFactor()...build().authenticated()}).
     */
    private DslValue managerBean(JavaSootMethod chainMethod, int index, String type) {
        String parameterName = chainMethod.getBody().getParameterLocal(index).getName();
        List<JavaSootMethod> candidates = SpringBeans.beanMethods(context, type).stream()
                .filter(JavaSootMethod::hasBody).toList();
        Optional<JavaSootMethod> bean = candidates.size() == 1 ? Optional.of(candidates.getFirst())
                : candidates.stream().filter(method -> method.getName().equals(parameterName)).findFirst();
        if (bean.isEmpty() || bean.get().equals(chainMethod)) {
            return null;
        }
        Map<Local, DslValue> values = root(bean.get(), new HashMap<>(), new Interpretation());
        return bean.get().getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                .map(stmt -> ((JReturnStmt) stmt).getOp()).filter(Local.class::isInstance)
                .map(values::get).filter(value -> value instanceof Manager || value instanceof FactoryValue)
                .findFirst().orElse(null);
    }

    /**
     * An {@code AuthenticationProcessInterceptor} bean method, with its {@code GrpcSecurity} parameter bound.
     */
    Interpretation grpcChain(JavaSootMethod beanMethod) {
        Map<Integer, DslValue> parameters = new HashMap<>();
        for (int i = 0; i < beanMethod.getParameterCount(); i++) {
            if (beanMethod.getParameterType(i) instanceof ClassType type
                    && type.getFullyQualifiedName().equals(GRPC_SECURITY)) {
                parameters.put(i, new Grpc());
            }
        }
        Interpretation result = new Interpretation();
        root(beanMethod, parameters, result);
        return result;
    }

    /**
     * HTTP-16: a custom DSL, an application {@code AbstractHttpConfigurer}: what its {@code init(http)} and
     * {@code configure(http)} configure, as rules that come after the chain's own.
     */
    /**
     * @param applied how the configurer is applied, for a finding: {@code http.with(..)}
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void customDsl(String type, Interpretation result, String applied, CodeRef where) {
        Optional<JavaSootClass> configurer = context.findClass(type)
                .filter(cls -> context.isApplication(cls.getType()));
        if (configurer.isEmpty()) {
            // Decision 0049 reads the authorization server's configurer.
            if (!type.equals(AUTHORIZATION_SERVER_CONFIGURER) && !CONFIGURERS_WITHOUT_RULES.contains(type)) {
                result.opaque.add(new Note(applied + " applies " + type + ", a configurer from a library AuthTracer"
                        + " doesn't read: its init and configure may add authorizeHttpRequests rules, filters or a"
                        + " securityMatcher the graph doesn't show", where));
            }
            return;
        }
        List<ClassType> chain = new ArrayList<>(List.of(configurer.get().getType()));
        chain.addAll(context.superClassesOf(configurer.get().getType()));
        for (String phase : List.of("init", "configure")) {
            for (ClassType candidate : chain) {
                // The HttpSecurity overload, not the bridge javac adds for the generic init(B).
                Optional<JavaSootMethod> method = context.findClass(candidate).stream()
                        .flatMap(cls -> cls.getMethods().stream())
                        .filter(found -> found.getName().equals(phase) && found.hasBody()
                                && found.getParameterCount() == 1
                                && found.getParameterType(0) instanceof ClassType parameter
                                && HTTP_BUILDERS.contains(parameter.getFullyQualifiedName()))
                        .min(Comparator.comparing(found -> ((ClassType) found.getParameterType(0))
                                .getFullyQualifiedName().equals(SpringNames.HTTP_SECURITY) ? 0 : 1));
                if (method.isPresent()) {
                    Interpretation own = new Interpretation();
                    root(method.get(), Map.of(0, new Http()), own);
                    result.deferred.addAll(own.rules);
                    result.deferred.addAll(own.deferred);
                    result.absorb(own);
                    break;
                }
            }
        }
    }

    /**
     * HTTP-16: the DSLs {@code META-INF/spring.factories} applies to every {@code HttpSecurity}, before the chain's
     * own: the application's, and every library jar's, since 7.1.1's {@code HttpSecurityConfiguration
     * #applyDefaultConfigurers} loads them with {@code SpringFactoriesLoader} from the whole classpath (javap).
     */
    Interpretation defaultDsls() {
        Interpretation result = new Interpretation();
        for (Path dir : context.input().resourceDirs()) {
            Path factories = dir.resolve("META-INF/spring.factories");
            if (!Files.isRegularFile(factories)) {
                continue;
            }
            try (var in = Files.newInputStream(factories)) {
                configurers(in).forEach(type -> customDsl(type, result, "META-INF/spring.factories",
                        CodeRef.ofClass(type)));
            }
            catch (IOException ex) {
                // An unreadable spring.factories applies nothing AuthTracer can see.
            }
        }
        // Without Spring Security's web configuration on the classpath, nothing loads them.
        List<Path> libraries = context.findClass(SpringNames.HTTP_SECURITY).isPresent() ? context.input().libraries()
                : List.of();
        for (Path library : libraries) {
            libraryConfigurers(library).forEach(type -> customDsl(type, result, "The META-INF/spring.factories of "
                    + library.getFileName(), CodeRef.ofClass(type)));
        }
        return result;
    }

    private static List<String> libraryConfigurers(Path library) {
        if (!Files.isRegularFile(library)) {
            return List.of();
        }
        String key;
        try {
            key = library + " " + Files.size(library) + " " + Files.getLastModifiedTime(library).toMillis();
        }
        catch (IOException ex) {
            return List.of();
        }
        return LIBRARY_FACTORIES.computeIfAbsent(key, ignored -> {
            try (ZipFile jar = new ZipFile(library.toFile())) {
                ZipEntry entry = jar.getEntry("META-INF/spring.factories");
                if (entry == null) {
                    return List.of();
                }
                try (var in = jar.getInputStream(entry)) {
                    return configurers(in);
                }
            }
            catch (IOException ex) {
                // A jar that can't be read applies nothing AuthTracer can see.
                return List.of();
            }
        });
    }

    /**
     * The {@code AbstractHttpConfigurer}s a {@code spring.factories} file lists.
     */
    private static List<String> configurers(InputStream in) throws IOException {
        Properties properties = new Properties();
        properties.load(in);
        return Arrays.stream(properties.getProperty(ABSTRACT_HTTP_CONFIGURER, "").split(","))
                .map(String::trim).filter(type -> !type.isEmpty()).toList();
    }

    /**
     * The lambdas a bean method returns, with their {@code parameterType} parameter bound to {@code receiver}.
     */
    Interpretation lambdas(JavaSootMethod beanMethod, String parameterType, Receiver receiver) {
        Interpretation result = new Interpretation();
        configuring = beanMethod.getSignature();
        interpretLambdas(beanMethod, parameterType, switch (receiver) {
            case HTTP -> new Http();
            case REGISTRY -> new Registry();
            case KOTLIN_RULES -> new KotlinRules();
            case WEB -> new Web();
        }, result);
        configuring = null;
        return result;
    }

    private void interpretLambdas(JavaSootMethod beanMethod, String parameterType, DslValue value,
            Interpretation result) {
        for (Stmt stmt : beanMethod.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition
                    && evaluate(definition.getRightOp(), Map.of(), Map.of(), result, stmt) instanceof Lambda lambda) {
                context.findMethod(lambda.method()).filter(JavaSootMethod::hasBody).ifPresent(body -> {
                    for (int i = 0; i < body.getParameterCount(); i++) {
                        if (body.getParameterType(i) instanceof ClassType type
                                && type.getFullyQualifiedName().equals(parameterType)) {
                            interpret(body, Map.of(i, value), result);
                        }
                    }
                });
            }
        }
    }

    /**
     * Reads a method that configures on its own (a bean method, a helper, a custom DSL's {@code configure}): what
     * it finds is placed there, and in the lambdas it declares.
     */
    private Map<Local, DslValue> root(JavaSootMethod method, Map<Integer, DslValue> parameters,
            Interpretation result) {
        MethodSignature outer = configuring;
        configuring = method.getSignature();
        try {
            return interpret(method, parameters, result);
        }
        finally {
            configuring = outer;
        }
    }

    @Might("Follow helper methods the bean method calls; today only the bean method and the lambdas it passes are read")
    private Map<Local, DslValue> interpret(JavaSootMethod method, Map<Integer, DslValue> parameters,
            Interpretation result) {
        Map<Local, DslValue> values = new HashMap<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition) {
                Value right = definition.getRightOp();
                if (definition.getLeftOp() instanceof Local local) {
                    DslValue value = evaluate(right, values, parameters, result, stmt);
                    if (value != null) {
                        values.put(local, value);
                    }
                }
                else if (definition.getLeftOp() instanceof JArrayRef array
                        && values.get(array.getBase()) instanceof Strings strings) {
                    DslValue element = right instanceof Local local ? values.get(local) : null;
                    Optional<String> text = text(right, values);
                    Optional<Matcher> matcher = asMatcher(element);
                    if (text.isPresent()) {
                        strings.values().add(text.get());
                    }
                    else if (element instanceof Manager manager) {
                        strings.managers().add(manager.requirement());
                    }
                    else if (customManager(element).isPresent()) {
                        strings.managers().add(customManager(element).get());
                    }
                    else if (matcher.isPresent()) {
                        strings.matchers().add(matcher.get());
                    }
                    else {
                        strings.unknown().add(right.getType().toString().equals("java.lang.String")
                                ? Matcher.NOT_CONSTANT : "RequestMatcher");
                    }
                }
            }
            else if (stmt.isInvokableStmt()) {
                stmt.asInvokableStmt().getInvokeExpr().ifPresent(invoke -> {
                    if (invoke.getMethodSignature().getName().equals("<init>")
                            && invoke instanceof AbstractInstanceInvokeExpr instance
                            && values.get(instance.getBase()) instanceof NewObject created
                            && created.type().equals(SERVER_MATCHERS + "PathPatternParserServerWebExchangeMatcher")) {
                        // new PathPatternParserServerWebExchangeMatcher(pattern[, method])
                        Optional<String> pattern = text(invoke.getArg(0), values);
                        String httpMethod = invoke.getArgCount() > 1 && values.get(invoke.getArg(1) instanceof Local arg
                                ? arg : null) instanceof HttpMethodValue value ? value.name() : null;
                        values.put(instance.getBase(), new MatcherValue(pattern.map(text -> Matcher.paths(httpMethod,
                                List.of(text))).orElse(Matcher.custom("ServerWebExchangeMatcher"))));
                    }
                    else if (invoke.getMethodSignature().getName().equals("<init>")
                            && invoke instanceof AbstractInstanceInvokeExpr instance
                            && values.get(instance.getBase()) instanceof NewObject created
                            && created.type().equals(REGEX_MATCHER) && invoke.getArgCount() >= 2) {
                        // new RegexRequestMatcher(pattern, httpMethod[, caseInsensitive])
                        Optional<String> pattern = text(invoke.getArg(0), values);
                        values.put(instance.getBase(), pattern.isEmpty() || invoke.getArgCount() > 2
                                ? new MatcherValue(Matcher.custom("new RegexRequestMatcher(..)"))
                                : new MatcherValue(Matcher.regex(text(invoke.getArg(1), values).orElse(null),
                                        pattern.get())));
                    }
                    else if (invoke.getMethodSignature().getName().equals("<init>")
                            && invoke instanceof AbstractInstanceInvokeExpr instance
                            && values.get(instance.getBase()) instanceof NewObject created
                            && created.type().equals(DISPATCHER_MATCHER)) {
                        // new DispatcherTypeRequestMatcher(type[, method])
                        String httpMethod = invoke.getArgs().stream().skip(1).map(arg -> argument(arg, values))
                                .filter(HttpMethodValue.class::isInstance).map(arg -> ((HttpMethodValue) arg).name())
                                .findFirst().orElse(null);
                        values.put(instance.getBase(), new MatcherValue(text(invoke.getArg(0), values)
                                .map(type -> Matcher.dispatch(httpMethod, List.of(type)))
                                .orElse(Matcher.custom("RequestMatcher"))));
                    }
                    else if (invoke.getMethodSignature().getName().equals("<init>")
                            && invoke instanceof AbstractInstanceInvokeExpr instance
                            && values.get(instance.getBase()) instanceof NewObject created
                            && created.type().equals(AUTHORIZATION_DECISION) && invoke.getArgCount() == 1
                            && invoke.getArg(0) instanceof IntConstant granted) {
                        // new AuthorizationDecision(true), a default decision for anyOf/allOf.
                        values.put(instance.getBase(), new NewObject(created.type(), String.valueOf(granted
                                .getValue() != 0)));
                    }
                    else if (invoke.getMethodSignature().getName().equals("<init>")
                            && invoke instanceof AbstractInstanceInvokeExpr instance
                            && values.get(instance.getBase()) instanceof NewObject created && invoke.getArgCount() == 1) {
                        text(invoke.getArg(0), values).ifPresent(arg ->
                                values.put(instance.getBase(), new NewObject(created.type(), arg)));
                    }
                    else if (invoke.getMethodSignature().getName().equals("setRoleHierarchy")
                            && invoke instanceof AbstractInstanceInvokeExpr instance
                            && values.get(instance.getBase()) instanceof Manager manager) {
                        // Decision 0063: a manager built in place and given the RoleHierarchy is widened by it.
                        values.put(instance.getBase(), new Manager(manager.requirement(), true));
                    }
                    else {
                        call(invoke, values, result, stmt);
                    }
                });
            }
        }
        return values;
    }

    private DslValue evaluate(Value right, Map<Local, DslValue> values, Map<Integer, DslValue> parameters,
            Interpretation result, Stmt stmt) {
        if (right instanceof JParameterRef parameter) {
            return parameters.get(parameter.getIndex());
        }
        if (right instanceof Local local) {
            return values.get(local);
        }
        if (right instanceof JCastExpr cast) {
            return cast.getOp() instanceof Local local ? values.get(local) : null;
        }
        if (right instanceof StringConstant constant) {
            return new Text(constant.getValue());
        }
        if (right instanceof JNewArrayExpr) {
            return new Strings(new ArrayList<>());
        }
        if (right instanceof JNewExpr created) {
            return closure(created.getType()).orElseGet(() -> new NewObject(created.getType().toString(), null));
        }
        if (right instanceof JStaticFieldRef field) {
            DslValue known = staticField(field.getFieldSignature().getDeclClassType().getFullyQualifiedName(),
                    field.getFieldSignature().getName());
            return known != null || !(field.getType() instanceof ClassType type) ? known
                    : injectedManager(type, field.getFieldSignature().getName());
        }
        if (right instanceof JInstanceFieldRef field && field.getType() instanceof ClassType type) {
            return injectedManager(type, field.getFieldSignature().getName());
        }
        if (right instanceof JDynamicInvokeExpr dynamic && GroovyCalls.of(dynamic).isPresent()) {
            return call(dynamic, values, result, stmt);
        }
        if (right instanceof JDynamicInvokeExpr dynamic) {
            for (Value argument : dynamic.getBootstrapArgs()) {
                if (argument instanceof MethodHandle handle
                        && handle.getReferenceSignature() instanceof MethodSignature target) {
                    return context.isApplication(target.getDeclClassType())
                            ? new Lambda(target, dynamic.getArgs().stream().map(arg -> argument(arg, values)).toList())
                            : new MethodReference(target);
                }
            }
            return null;
        }
        if (right instanceof AbstractInvokeExpr invoke) {
            return call(invoke, values, result, stmt);
        }
        return null;
    }

    private static DslValue staticField(String owner, String name) {
        return switch (owner) {
            case HTTP_METHOD -> new HttpMethodValue(name);
            case STATIC_RESOURCE_LOCATION, DISPATCHER_TYPE -> new Text(name);
            default -> null;
        };
    }

    /**
     * A Groovy closure ({@code { registry -> ... }}) is a class extending {@code Closure}; its {@code doCall} is the
     * body, called with the closure's argument.
     */
    private Optional<DslValue> closure(ClassType type) {
        if (!context.isApplication(type) || context.superClassesOf(type).stream()
                .noneMatch(superClass -> superClass.getFullyQualifiedName().equals(GROOVY_CLOSURE))) {
            return Optional.empty();
        }
        return context.findClass(type).flatMap(cls -> cls.getMethods().stream()
                .filter(method -> method.getName().equals("doCall") && method.hasBody())
                .max(Comparator.comparingInt(JavaSootMethod::getParameterCount)))
                .map(doCall -> new Lambda(doCall.getSignature(), List.of()));
    }

    /**
     * Dynamic Groovy: {@code registry.requestMatchers('/a').permitAll()} is a call by name on whatever the receiver
     * holds, so it is read like the Java call. Static calls ({@code AuthorityAuthorizationManager.hasRole('X')}) and
     * static properties ({@code HttpMethod.POST}) have the class as their receiver; varargs arrive as separate
     * arguments.
     */
    private DslValue groovyCall(GroovyCalls.Call call, Map<Local, DslValue> values, Interpretation result, Stmt stmt) {
        List<DslValue> args = call.args().stream().map(arg -> argument(arg, values)).toList();
        Optional<String> owner = call.staticOwner();
        return switch (call.type()) {
            case "cast" -> argument(call.receiver(), values);
            case "getProperty" -> owner.isPresent() ? staticField(owner.get(), call.name())
                    : instanceCall(null, argument(call.receiver(), values), "get" + Character.toUpperCase(call.name()
                            .charAt(0)) + call.name().substring(1), List.of(), result, stmt);
            case "invoke" -> {
                List<DslValue> spread = GROOVY_VARARGS.contains(call.name()) ? varargs(args) : args;
                if (owner.isPresent()) {
                    DslValue matcher = matcherFactory(owner.get(), call.name(), spread);
                    yield matcher != null ? matcher : managerFactory(owner.get(), call.name(), null, spread);
                }
                yield instanceCall(call.receiverType().toString(), argument(call.receiver(), values), call.name(),
                        spread, result, stmt);
            }
            default -> null;
        };
    }

    /**
     * Groovy passes {@code requestMatchers('/a', '/b')} as two arguments where Java passes one array.
     */
    private List<DslValue> varargs(List<DslValue> args) {
        int start = !args.isEmpty() && args.getFirst() instanceof HttpMethodValue ? 1 : 0;
        if (args.size() == start || args.subList(start, args.size()).stream().anyMatch(arg -> arg instanceof Strings)) {
            return args;
        }
        Strings array = new Strings(new ArrayList<>());
        for (DslValue arg : args.subList(start, args.size())) {
            if (arg instanceof Text text) {
                array.values().add(text.value());
            }
            else if (arg instanceof Manager manager) {
                array.managers().add(manager.requirement());
            }
            else if (asMatcher(arg).isPresent()) {
                array.matchers().add(asMatcher(arg).orElseThrow());
            }
            else {
                array.unknown().add("RequestMatcher");
            }
        }
        List<DslValue> spread = new ArrayList<>(args.subList(0, start));
        spread.add(array);
        return spread;
    }

    private DslValue call(AbstractInvokeExpr invoke, Map<Local, DslValue> values, Interpretation result, Stmt stmt) {
        Optional<GroovyCalls.Call> groovy = GroovyCalls.of(invoke);
        if (groovy.isPresent()) {
            return groovyCall(groovy.get(), values, result, stmt);
        }
        List<DslValue> arguments = invoke.getArgs().stream().map(arg -> argument(arg, values)).toList();
        if (helper(invoke.getMethodSignature(), arguments)) {
            return follow(invoke.getMethodSignature(), arguments, result, stmt);
        }
        if (!(invoke instanceof AbstractInstanceInvokeExpr instance)) {
            List<DslValue> args = invoke.getArgs().stream().map(arg -> argument(arg, values)).toList();
            String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
            if (KOTLIN_DSL_ENTRY.contains(owner) && invoke.getMethodSignature().getName().equals("invoke")
                    && args.size() == 2 && args.getFirst() instanceof Http && args.getLast() instanceof Lambda lambda) {
                // http { ... }: HttpSecurityDslKt.invoke(http, lambda), the lambda's receiver is the DSL.
                result.rules.addAll(kotlinDslBeanRules);
                result.authorizes |= kotlinDslBeanAuthorizes;
                interpretLambda(lambda, new Http(), result);
                return null;
            }
            if (invoke.getMethodSignature().getName().equals("authorize$default") && !args.isEmpty()
                    && args.getFirst() instanceof KotlinRules) {
                kotlinRule(withDefaults(invoke, args), result, stmt);
                return null;
            }
            DslValue matcher = matcherFactory(owner, invoke.getMethodSignature().getName(), args);
            return matcher != null ? matcher : managerFactory(owner, invoke.getMethodSignature().getName(),
                    invoke.getMethodSignature().getParameterTypes().stream().map(Object::toString).toList(), args);
        }
        List<DslValue> args = new ArrayList<>(invoke.getArgs().stream().map(arg -> argument(arg, values)).toList());
        if (values.get(instance.getBase()) instanceof Http && invoke.getMethodSignature().getName().equals("with")
                && !args.isEmpty() && !(args.getFirst() instanceof NewObject)) {
            // A configurer from a factory method, e.g. a library's aadWebApplication(): known by its type.
            args.set(0, new NewObject(invoke.getArg(0).getType().toString(), null));
        }
        return instanceCall(invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName(),
                values.get(instance.getBase()), invoke.getMethodSignature().getName(), args, result, stmt);
    }

    /**
     * @param owner the class the call is declared on, {@code null} when unknown
     */
    private DslValue instanceCall(String owner, DslValue receiver, String name, List<DslValue> args,
            Interpretation result, Stmt stmt) {
        if (receiver instanceof AuthorizationServer || AUTHORIZATION_SERVER_CONFIGURER.equals(owner)) {
            // Its endpoints' matcher, which the reference configuration makes the chain's securityMatcher.
            return name.equals("getEndpointsMatcher") ? new MatcherValue(authorizationServerEndpoints())
                    : new AuthorizationServer();
        }
        if (receiver instanceof Http) {
            if (name.equals("oauth2AuthorizationServer") && first(args) instanceof Lambda lambda) {
                interpretLambda(lambda, new AuthorizationServer(), result);
            }
            if (name.equals("securityMatcher") && !args.isEmpty()) {
                result.securityMatcher = args.getFirst() instanceof Strings patterns && patterns.matchers().isEmpty()
                        ? patterns(null, patterns)
                        : asMatcher(args.getFirst()).orElse(Matcher.custom("securityMatcher(RequestMatcher)"));
            }
            if (name.equals("securityMatchers") && !args.isEmpty() && args.getFirst() instanceof Lambda lambda) {
                interpretLambda(lambda, new SecurityMatchers(), result);
            }
            if (name.equals("with") && !args.isEmpty() && args.getFirst() instanceof NewObject created) {
                customDsl(created.type(), result, "http.with(..)", codeRef(stmt));
            }
            if (name.equals("objectPostProcessor")) {
                // The builder's own post-processor, which every configurer added after it gets (7.1.1
                // AbstractConfiguredSecurityBuilder#add).
                postProcessor(first(args), "objectPostProcessor", result, stmt);
            }
            if ((name.equals("formLogin") || name.equals("logout")) && !reactive && !args.isEmpty()
                    && args.getFirst() instanceof Lambda lambda) {
                LoginUrls urls = new LoginUrls(name.equals("logout"), stmt.getPositionInfo().getStmtPosition()
                        .getFirstLine());
                interpretLambda(lambda, urls, result);
                result.logins.add(urls);
            }
            // Decision 0093: CSRF protection decides which methods the logout URL takes.
            if (name.equals("csrf")) {
                Csrf csrf = new Csrf();
                if (first(args) instanceof MethodReference reference) {
                    csrf.disabled |= reference.method().getName().equals("disable");
                }
                else if (first(args) instanceof Lambda lambda) {
                    interpretLambda(lambda, csrf, result);
                }
                result.csrfOff.add(csrf.disabled);
            }
            if ((name.equals("authorizeHttpRequests") || name.equals("authorizeExchange")) && !args.isEmpty()) {
                result.authorizes = true;
                if (args.getFirst() instanceof Lambda lambda) {
                    boolean kotlin = owner != null && owner.endsWith("Dsl");
                    interpretLambda(lambda, kotlin ? new KotlinRules() : new Registry(), result);
                }
                else {
                    // A customizer from a bean or a field: its rules are unknown, not absent.
                    unreadRules(name + "(customizer)", result, stmt);
                }
            }
            return new Http();
        }
        if (receiver instanceof GrpcServlet servlet) {
            // excluding(..), its only method.
            Set<String> excluded = new HashSet<>(servlet.excluded());
            texts(args).ifPresent(excluded::addAll);
            return new GrpcServlet(excluded);
        }
        if (receiver instanceof Csrf csrf) {
            csrf.disabled |= name.equals("disable");
            return csrf;
        }
        if (receiver instanceof LoginUrls urls) {
            Optional<String> text = args.size() == 1 && args.getFirst() instanceof Text value
                    ? Optional.of(value.value()) : Optional.empty();
            // The Kotlin DSL's FormLoginDsl and LogoutDsl set properties: loginPage = "/signin" is setLoginPage(..).
            switch (name) {
                case "loginPage", "setLoginPage" -> text.ifPresent(value -> urls.calls()
                        .add(state -> state.page = value));
                case "loginProcessingUrl", "setLoginProcessingUrl" -> text.ifPresent(value -> urls.calls()
                        .add(state -> state.processing = value));
                case "failureUrl", "setFailureUrl" -> text.ifPresent(value -> urls.calls().add(state -> {
                    state.failure = value;
                    state.noFailure = false;
                }));
                // 7.1.1: a failure handler clears the failure URL.
                case "failureHandler", "failureForwardUrl", "setAuthenticationFailureHandler" -> urls.calls()
                        .add(state -> state.noFailure = true);
                case "logoutUrl", "setLogoutUrl" -> text.ifPresent(value -> urls.calls()
                        .add(state -> state.logoutUrl = value));
                case "logoutSuccessUrl", "setLogoutSuccessUrl" -> text.ifPresent(value -> urls.calls().add(state -> {
                    state.logoutSuccess = value;
                    state.noSuccess = false;
                }));
                case "logoutSuccessHandler", "setLogoutSuccessHandler" -> urls.calls()
                        .add(state -> state.noSuccess = true);
                case "logoutRequestMatcher", "setLogoutRequestMatcher" -> {
                    Matcher matcher = args.stream().findFirst().flatMap(this::asMatcher)
                            .orElse(Matcher.custom("RequestMatcher"));
                    urls.calls().add(state -> state.logoutMatcher = matcher);
                }
                // permitAll(false) undoes it.
                case "permitAll", "setPermitAll" -> {
                    boolean permitAll = args.isEmpty() || !(args.getFirst() instanceof Number value)
                            || value.value() != 0;
                    urls.calls().add(state -> state.permitAll = permitAll);
                }
                default -> {
                }
            }
            return urls;
        }
        if (receiver instanceof Grpc) {
            if (name.equals("authorizeRequests") && !args.isEmpty() && args.getFirst() instanceof Lambda lambda) {
                result.authorizes = true;
                interpretLambda(lambda, new GrpcRegistry(), result);
            }
            return new Grpc();
        }
        if (receiver instanceof GrpcRegistry) {
            return switch (name) {
                case "methods" -> new GrpcCall(texts(args).map(Matcher::grpc)
                        .orElse(Matcher.custom("methods(..)")), false);
                case "allRequests" -> new GrpcCall(Matcher.grpc(List.of("*")), false);
                default -> new GrpcRegistry();
            };
        }
        if (receiver instanceof GrpcCall call) {
            if (name.equals("not")) {
                return new GrpcCall(call.matcher(), !call.not());
            }
            requirement(name, args, spel).ifPresent(requirement -> result.rules.add(new Rule(call.matcher(),
                    call.not() ? Requirement.not(requirement) : requirement,
                    stmt.getPositionInfo().getStmtPosition().getFirstLine())));
            return new GrpcRegistry();
        }
        if (receiver instanceof KotlinRules) {
            return switch (name) {
                case "getPermitAll" -> new DslManager(Requirement.permitAll());
                case "getDenyAll" -> new DslManager(Requirement.denyAll());
                case "getAuthenticated" -> new DslManager(Requirement.authenticated());
                case "getFullyAuthenticated" -> new DslManager(Requirement.fullyAuthenticated());
                case "getAnyRequest", "getAnyExchange" -> new MatcherValue(Matcher.ANY_REQUEST);
                case "authorize" -> {
                    kotlinRule(args, result, stmt);
                    yield null;
                }
                default -> requirement(name, args, spel).map(requirement -> (DslValue) new DslManager(requirement))
                        .orElse(null);
            };
        }
        if (receiver instanceof SecurityMatchers) {
            if (name.equals("requestMatchers") || name.equals("anyRequest")) {
                result.configured.add(name.equals("anyRequest") ? Matcher.ANY_REQUEST : matcher(args));
                result.securityMatcher = Matcher.anyOf(result.configured, List.of());
            }
            return new SecurityMatchers();
        }
        if (receiver instanceof Web) {
            return name.equals("ignoring") ? new IgnoredRequests() : new Web();
        }
        if (receiver instanceof IgnoredRequests) {
            if (name.equals("requestMatchers")) {
                result.ignored.add(new Rule(matcher(args), Requirement.permitAll(),
                        stmt.getPositionInfo().getStmtPosition().getFirstLine()));
            }
            return name.equals("and") ? new Web() : new IgnoredRequests();
        }
        if (receiver instanceof Registry) {
            return switch (name) {
                case "anyRequest", "anyExchange" -> new AuthorizedUrl(Matcher.ANY_REQUEST, false);
                case "requestMatchers", "pathMatchers", "matchers" -> new AuthorizedUrl(matcher(args), false);
                case "dispatcherTypeMatchers" -> new AuthorizedUrl(dispatcherTypes(args), false);
                case "withObjectPostProcessor" -> {
                    postProcessor(first(args), "withObjectPostProcessor", result, stmt);
                    yield new Registry();
                }
                default -> new Registry();
            };
        }
        if (receiver instanceof MatcherBuilder builder) {
            return switch (name) {
                // A new base path replaces the builder's (7.1.1 PathPatternRequestMatcher.Builder#basePath).
                case "basePath" -> args.size() == 1 && args.getFirst() instanceof Text base
                        ? new MatcherBuilder(base.value()) : new MatcherValue(Matcher.custom(
                                "PathPatternRequestMatcher.Builder"));
                case "matcher" -> {
                    String method = args.size() == 2 && args.getFirst() instanceof HttpMethodValue value
                            ? value.name() : null;
                    yield args.getLast() instanceof Text pattern
                            ? new MatcherValue(Matcher.paths(method, List.of(builder.prefixed(pattern.value()))))
                            : new MatcherValue(Matcher.custom("PathPatternRequestMatcher"));
                }
                default -> builder;
            };
        }
        if (receiver instanceof StaticResources resources) {
            List<String> named = texts(args).orElse(List.of());
            return switch (name) {
                case "atCommonLocations" -> new StaticResources(List.copyOf(STATIC_RESOURCES.keySet()));
                case "at" -> new StaticResources(named);
                case "excluding" -> new StaticResources(resources.locations().stream()
                        .filter(location -> !named.contains(location)).toList());
                default -> resources;
            };
        }
        if (receiver instanceof WebExpressionBuilder && name.equals("expression") && args.size() == 1
                && args.getFirst() instanceof Text expression) {
            return new NewObject(WEB_EXPRESSION_MANAGER, expression.value());
        }
        if (receiver instanceof EndpointMatcher endpoints) {
            Set<String> excluded = new HashSet<>(endpoints.excluded());
            return switch (name) {
                case "excluding" -> {
                    excluded.addAll(endpointIds(args));
                    yield new EndpointMatcher(endpoints.ids(), excluded, endpoints.links(), endpoints.method());
                }
                case "excludingLinks" -> new EndpointMatcher(endpoints.ids(), excluded, false, endpoints.method());
                case "withHttpMethod" -> new EndpointMatcher(endpoints.ids(), excluded, endpoints.links(),
                        !args.isEmpty() && args.getFirst() instanceof HttpMethodValue value ? value.name() : null);
                default -> endpoints;
            };
        }
        if (receiver instanceof FactorsBuilder builder) {
            return factorsCall(builder, name, args);
        }
        if (receiver instanceof FactoryValue factory) {
            // mfa.hasRole("ADMIN"): ROLE_ (the factory's default) and the factors.
            return requirement(name, args, DEFAULT_ROLES).map(requirement -> new Manager(MultiFactor.addsFactors(name)
                    ? MultiFactor.require(requirement, factory.additional()) : requirement)).orElse(null);
        }
        if (receiver instanceof Conditional conditional) {
            Requirement branch = !args.isEmpty() && args.getFirst() instanceof Manager manager
                    ? manager.requirement() : Requirement.expression("AuthorizationManager");
            switch (name) {
                case "whenTrue" -> conditional.whenTrue = branch;
                case "whenFalse" -> conditional.whenFalse = branch;
                case "build" -> {
                    return conditional(conditional);
                }
                default -> {
                }
            }
            return conditional;
        }
        if (receiver instanceof AuthorizedUrl url) {
            if (name.equals("not")) {
                return new AuthorizedUrl(url.matcher(), !url.not());
            }
            if (name.equals("hasVariable")) {
                return new UrlVariable(url, args.size() == 1 && args.getFirst() instanceof Text variable
                        ? variable.value() : "?");
            }
            Requirement requirement = requirement(name, args, spel).orElseGet(() -> {
                // An authority that isn't a constant, or a manager AuthTracer doesn't know: the rule still takes the
                // requests it matches, with a requirement shown as unread.
                String unread = name + (AUTHORITY_METHODS.contains(name) ? "(?)" : "(..)");
                result.unread.add(new Unread(url.matcher(), unread));
                return Requirement.expression(unread);
            });
            if (name.equals("access") && requirement.kind() == Requirement.Kind.EXPRESSION
                    && requirement.decidedBy() == null && requirement.expression().startsWith("access(")) {
                // Decision 0064: a manager AuthTracer can't find the code of is reported, not only shown as opaque.
                result.unread.add(new Unread(url.matcher(), requirement.expression()));
            }
            result.rules.add(new Rule(url.matcher(), url.not() ? Requirement.not(requirement) : requirement,
                    stmt.getPositionInfo().getStmtPosition().getFirstLine(), !reactive && !(name.equals("access")
                            && (args.getFirst() instanceof Manager manager && !manager.hierarchy()
                                    || args.getFirst() instanceof NewObject created
                                    && created.type().equals(WEB_EXPRESSION_MANAGER)))));
            return new Registry();
        }
        if (receiver instanceof UrlVariable variable && name.equals("equalTo")) {
            // The variable is compared with what the function reads from the Authentication, per request.
            Requirement requirement = Requirement.expression("hasVariable(" + variable.variable() + ").equalTo(..)");
            result.rules.add(new Rule(variable.url().matcher(), variable.url().not() ? Requirement.not(requirement)
                    : requirement, stmt.getPositionInfo().getStmtPosition().getFirstLine()));
            return new Registry();
        }
        return null;
    }

    /**
     * {@code authorize(pattern, manager)}, {@code authorize(method, pattern, manager)}, {@code authorize(matcher,
     * manager)} and the {@code servletPath} forms. Patterns go through the Builder bean, as in the Java DSL; a
     * {@code servletPath} replaces its base path (7.1.1 {@code AuthorizeHttpRequestsDsl#get}). Every form has a
     * matcher and a manager, so {@code args} has at least two.
     */
    private void kotlinRule(List<DslValue> args, Interpretation result, Stmt stmt) {
        DslValue access = args.getLast();
        List<DslValue> match = args.subList(0, args.size() - 1);
        String method = match.getFirst() instanceof HttpMethodValue value ? value.name() : null;
        List<String> texts = match.stream().filter(Text.class::isInstance).map(arg -> ((Text) arg).value()).toList();
        Matcher matcher = match.getFirst() instanceof Defaulted ? Matcher.ANY_REQUEST
                : asMatcher(match.getFirst()).orElseGet(() -> texts.isEmpty() ? Matcher.custom("RequestMatcher")
                        : Matcher.paths(method, List.of(texts.size() > 1
                                ? new MatcherBuilder(texts.get(1)).prefixed(texts.getFirst())
                                : requestMatcherBuilder.prefixed(texts.getFirst()))));
        Requirement requirement = access instanceof DslManager built ? built.requirement()
                : access instanceof Manager built ? built.requirement()
                        : access instanceof Defaulted ? Requirement.authenticated() : access(access);
        result.rules.add(new Rule(matcher, requirement, stmt.getPositionInfo().getStmtPosition().getFirstLine(),
                !reactive && !(access instanceof Manager) && !(access instanceof NewObject)));
    }

    /**
     * A Kotlin call that leaves out defaulted arguments, {@code authorize$default(dsl, a, b, mask, marker)}: the
     * arguments without the receiver, mask and marker, {@link Defaulted} where the default applies.
     */
    private static List<DslValue> withDefaults(AbstractInvokeExpr invoke, List<DslValue> args) {
        int mask = invoke.getArg(invoke.getArgCount() - 2) instanceof IntConstant constant ? constant.getValue() : 0;
        List<DslValue> explicit = new ArrayList<>();
        for (int i = 1; i < args.size() - 2; i++) {
            explicit.add((mask & (1 << (i - 1))) != 0 ? new Defaulted() : args.get(i));
        }
        return explicit;
    }

    private void interpretLambda(Lambda lambda, DslValue argument, Interpretation result) {
        context.findMethod(lambda.method()).filter(JavaSootMethod::hasBody).ifPresent(body -> {
            Map<Integer, DslValue> parameters = new HashMap<>();
            // A lambda that uses this captures it first; it is the body's receiver, not a parameter.
            int receiver = body.isStatic() ? 0 : 1;
            for (int i = receiver; i < lambda.captured().size() && i - receiver < body.getParameterCount() - 1; i++) {
                if (lambda.captured().get(i) != null) {
                    parameters.put(i - receiver, lambda.captured().get(i));
                }
            }
            parameters.put(body.getParameterCount() - 1, argument);
            interpret(body, parameters, result);
        });
    }

    /**
     * Whether a call is to an application method the configuration is split into: one that takes the
     * {@code HttpSecurity} or a registry ({@code apiRules(http)}), or one returning a customizer for
     * {@code authorizeHttpRequests(..)}.
     */
    private boolean helper(MethodSignature target, List<DslValue> args) {
        boolean configures = args.stream().anyMatch(arg -> arg instanceof Http || arg instanceof Registry
                || arg instanceof KotlinRules);
        boolean customizer = target.getType() instanceof ClassType type
                && CUSTOMIZERS.contains(type.getFullyQualifiedName());
        return (configures || customizer) && context.isApplication(target.getDeclClassType());
    }

    /**
     * Reads a helper method with its arguments bound, as a lambda is; its value is what it returns. One AuthTracer
     * can't read (abstract, too deep, recursive) that takes the {@code HttpSecurity} may set any rules.
     */
    private DslValue follow(MethodSignature target, List<DslValue> args, Interpretation result, Stmt stmt) {
        Optional<JavaSootMethod> method = context.findMethod(target).filter(JavaSootMethod::hasBody);
        if (method.isEmpty() || following.size() >= MAX_FOLLOWED || !following.add(target)) {
            if (args.stream().anyMatch(Http.class::isInstance)) {
                result.authorizes = true;
                unreadRules("rules set in " + target.getName() + "(..)", result, stmt);
            }
            return null;
        }
        try {
            Map<Integer, DslValue> parameters = new HashMap<>();
            for (int i = 0; i < args.size(); i++) {
                if (args.get(i) != null) {
                    parameters.put(i, args.get(i));
                }
            }
            Map<Local, DslValue> values = root(method.get(), parameters, result);
            return method.get().getBody().getStmts().stream().filter(JReturnStmt.class::isInstance)
                    .map(returned -> ((JReturnStmt) returned).getOp()).filter(Local.class::isInstance)
                    .map(local -> values.get((Local) local)).filter(Objects::nonNull).findFirst()
                    .orElse(null);
        }
        finally {
            following.remove(target);
        }
    }

    /**
     * Rules AuthTracer can't read: one opaque rule for every request, ahead of anything after it.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private static void unreadRules(String what, Interpretation result, Stmt stmt) {
        result.rules.add(new Rule(Matcher.ANY_REQUEST, Requirement.expression(what),
                stmt.getPositionInfo().getStmtPosition().getFirstLine()));
        result.unread.add(new Unread(Matcher.ANY_REQUEST, what));
    }

    /**
     * {@code requestMatchers(..)} on a registry: {@code String} patterns go through the
     * {@code PathPatternRequestMatcher.Builder} bean, if there is one; {@code RequestMatcher}s are read when they come
     * from a known factory.
     */
    private Matcher matcher(List<DslValue> args) {
        // A pattern that isn't a constant may match any request: decision 0051's custom part.
        if (args.size() == 1 && args.getFirst() instanceof Strings array && array.matchers().isEmpty()
                && !(array.values().isEmpty() && array.unknown().isEmpty())) {
            return patterns(null, array);
        }
        if (args.size() == 2 && args.get(0) instanceof HttpMethodValue method && args.get(1) instanceof Strings patterns) {
            return patterns(method.name(), patterns);
        }
        if (args.size() == 1 && args.getFirst() instanceof HttpMethodValue method) {
            return Matcher.paths(method.name(), List.of(requestMatcherBuilder.prefixed("/**")));
        }
        if (args.size() == 1 && args.getFirst() instanceof Strings array && !array.matchers().isEmpty()) {
            return Matcher.anyOf(array.matchers(), array.unknown().isEmpty() ? List.of()
                    : List.of("requestMatchers(RequestMatcher...)"));
        }
        return Matcher.custom("requestMatchers(RequestMatcher...)");
    }

    /**
     * HTTP-19: an {@code ObjectPostProcessor} for the authorization configurer. 7.1.1 hands it the
     * {@code AuthorizationFilter} and the request {@code AuthorizationManager}, each only when it is of the
     * processor's type argument ({@code SecurityConfigurerAdapter$CompositeObjectPostProcessor}). One of the
     * application's for the filter that sets only its dispatch flags and returns it is read; any other may replace or
     * wrap the filter or the manager, so the rules may not be what decides.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void postProcessor(DslValue processor, String call, Interpretation result, Stmt stmt) {
        String type = processor instanceof NewObject created ? created.type() : null;
        Optional<JavaSootMethod> body = Optional.ofNullable(type).flatMap(context::findClass)
                .filter(cls -> context.classFiles().declaration(type).supertypes().contains(FILTER_POST_PROCESSOR))
                .flatMap(cls -> cls.getMethods().stream().filter(method -> method.getName().equals("postProcess")
                        && method.getParameterTypes().equals(List.of(context.type(AUTHORIZATION_FILTER))))
                        .filter(JavaSootMethod::hasBody).findFirst());
        if (body.isPresent() && setsDispatchFlags(body.get())) {
            result.errorDispatchUnchecked |= body.get().getBody().getStmts().stream()
                    .flatMap(statement -> Locals.invoke(statement).stream())
                    .anyMatch(invoke -> invoke.getMethodSignature().getName().equals("setFilterErrorDispatch")
                            && !invoke.getArg(0).equals(IntConstant.getInstance(1)));
            return;
        }
        result.opaque.add(new Note(call + "(" + (type == null ? "ObjectPostProcessor" : type) + ") post-processes"
                + " the authorization configurer's AuthorizationFilter or AuthorizationManager, which it may replace or"
                + " wrap: requests may not be decided by the rules shown", codeRef(stmt)));
    }

    /**
     * Whether a filter's post-processor only sets its dispatch flags ({@code setObserveOncePerRequest},
     * {@code setFilterErrorDispatch}, {@code setFilterAsyncDispatch}) or its event publisher, and returns the filter
     * it was given.
     */
    private static boolean setsDispatchFlags(JavaSootMethod method) {
        Local filter = method.getBody().getParameterLocal(0);
        return method.getBody().getStmts().stream().allMatch(stmt -> stmt instanceof JIdentityStmt
                || stmt instanceof JReturnStmt returned && returned.getOp().equals(filter)
                || Locals.invoke(stmt).filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr instance
                        && instance.getBase().equals(filter)
                        && DISPATCH_SETTERS.contains(invoke.getMethodSignature().getName())).isPresent());
    }

    private static DslValue first(List<DslValue> args) {
        return args.isEmpty() ? null : args.getFirst();
    }

    private CodeRef codeRef(Stmt stmt) {
        return MethodNames.codeRef(configuring).atLine(stmt.getPositionInfo().getStmtPosition().getFirstLine());
    }

    /**
     * HTTP-05: {@code dispatcherTypeMatchers([method,] types)}; a type that isn't a constant may be {@code REQUEST}.
     */
    private static Matcher dispatcherTypes(List<DslValue> args) {
        String method = args.getFirst() instanceof HttpMethodValue value ? value.name() : null;
        return args.getLast() instanceof Strings types
                ? Matcher.anyOf(List.of(Matcher.dispatch(method, types.values())), types.unknown())
                : Matcher.custom("RequestMatcher");
    }

    /**
     * String patterns through the {@code PathPatternRequestMatcher.Builder}, with any that aren't constants as parts
     * that may match.
     */
    private Matcher patterns(String httpMethod, Strings patterns) {
        return Matcher.anyOf(List.of(Matcher.paths(httpMethod, patterns.values().stream()
                .map(requestMatcherBuilder::prefixed).toList())), patterns.unknown());
    }

    /**
     * What {@code OAuth2AuthorizationServerConfigurer.getEndpointsMatcher()} matches (7.1.1: each endpoint's own
     * matcher, and the JWK set's): the authorization server's endpoints decision 0049 finds.
     */
    @Supports(Feature.LIBRARY_ENDPOINTS)
    private Matcher authorizationServerEndpoints() {
        List<Matcher> endpoints = new AuthorizationServerEndpoints(context).detect().stream()
                .map(endpoint -> Matcher.paths(endpoint.ingress().httpMethod(), List.of(endpoint.ingress().route())))
                .toList();
        return endpoints.isEmpty() ? Matcher.custom("the authorization server's endpoints (none)")
                : Matcher.anyOf(endpoints, List.of());
    }

    private Optional<Matcher> asMatcher(DslValue value) {
        if (value instanceof MatcherValue matcher) {
            return Optional.of(matcher.matcher());
        }
        if (value instanceof Lambda lambda) {
            // HTTP-06: the captured constants, without a receiver the lambda captures first.
            int receiver = context.findMethod(lambda.method()).filter(JavaSootMethod::isStatic).isPresent() ? 0 : 1;
            return MatcherLambdas.read(context, lambda.method(), lambda.captured().stream().skip(receiver)
                    .map(captured -> captured instanceof Text text ? text.value() : null).toList(), servletPath);
        }
        if (value instanceof MethodReference reference) {
            return MatcherLambdas.read(context, reference.method(), List.of(), servletPath);
        }
        if (value instanceof GrpcServlet servlet) {
            List<String> patterns = grpcServices.stream().filter(service -> !servlet.excluded().contains(service))
                    .sorted().map(service -> servletPath + "/" + service + "/**").toList();
            return Optional.of(patterns.isEmpty() ? Matcher.custom("GrpcRequest.toAnyService() (no gRPC services)")
                    : Matcher.paths(null, patterns));
        }
        if (value instanceof EndpointMatcher endpoints) {
            ActuatorEndpoints actuator = new ActuatorEndpoints(context);
            List<String> patterns = new ArrayList<>();
            (endpoints.ids() == null ? actuator.exposed().keySet() : endpoints.ids()).stream()
                    .filter(id -> !endpoints.excluded().contains(id)).forEach(id -> {
                        patterns.add(servletPath + actuator.path(id));
                        patterns.add(servletPath + actuator.path(id) + "/**");
                    });
            if (endpoints.links()) {
                patterns.add(servletPath + (actuator.basePath().isEmpty() ? "/" : actuator.basePath()));
            }
            return Optional.of(patterns.isEmpty() ? Matcher.custom("EndpointRequest (no exposed endpoint)")
                    : Matcher.paths(endpoints.method(), patterns));
        }
        if (value instanceof StaticResources resources) {
            // Relative to the DispatcherServlet path, and not through the Builder bean.
            return Optional.of(Matcher.paths(null, resources.locations().stream()
                    .flatMap(location -> STATIC_RESOURCES.getOrDefault(location, List.of()).stream())
                    .map(pattern -> servletPath + pattern).toList()));
        }
        return Optional.empty();
    }

    /**
     * {@code RequestMatcher} factories: {@code RegexRequestMatcher.regexMatcher(..)} (HTTP-03),
     * {@code PathPatternRequestMatcher.pathPattern(..)}/{@code withDefaults()} (HTTP-04), Spring Boot's
     * {@code PathRequest} (HTTP-07), and {@code WebExpressionAuthorizationManager.withDefaults()} (HTTP-11). Where a
     * class has one static factory (7.1.1 {@code regexMatcher}, Boot 4.1.1's reactive {@code toStaticResources} and
     * {@code toAnyService}), any static call on it is that factory.
     */
    private DslValue matcherFactory(String owner, String name, List<DslValue> args) {
        String method = !args.isEmpty() && args.getFirst() instanceof HttpMethodValue value ? value.name() : null;
        return switch (owner) {
            case REGEX_MATCHER -> args.getLast() instanceof Text pattern
                    ? new MatcherValue(Matcher.regex(method, pattern.value()))
                    : args.size() == 1 && method != null ? new MatcherValue(Matcher.regex(method, ".*"))
                            : new MatcherValue(Matcher.custom("RegexRequestMatcher"));
            case ENDPOINT_REQUEST, REACTIVE_ENDPOINT_REQUEST ->
                switch (name) {
                    case "toAnyEndpoint" -> new EndpointMatcher(null, Set.of(), true, null);
                    case "to" -> new EndpointMatcher(endpointIds(args), Set.of(), false, null);
                    case "toLinks" -> new EndpointMatcher(Set.of(), Set.of(), true, null);
                    default -> null;
                };
            case PATH_PATTERN_MATCHER -> switch (name) {
                case "withDefaults", "withPathPatternParser" -> new MatcherBuilder(null);
                case "pathPattern" -> args.getLast() instanceof Text pattern
                        ? new MatcherValue(Matcher.paths(method, List.of(pattern.value())))
                        : new MatcherValue(Matcher.custom("PathPatternRequestMatcher"));
                default -> null;
            };
            case PATH_REQUEST -> switch (name) {
                case "toStaticResources" -> new StaticResources(List.of());
                case "toH2Console" -> new MatcherValue(Matcher.paths(null, List.of(context.properties()
                        .get("spring.h2.console.path").orElse("/h2-console") + "/**")));
                default -> null;
            };
            // withDefaults() or withExpressionHandler(..).
            case WEB_EXPRESSION_MANAGER -> new WebExpressionBuilder();
            // RX-03: ServerWebExchangeMatchers.pathMatchers(..)/anyExchange(), and Boot's reactive PathRequest.
            case SERVER_MATCHERS + "ServerWebExchangeMatchers" -> switch (name) {
                case "anyExchange" -> new MatcherValue(Matcher.ANY_REQUEST);
                case "pathMatchers" -> {
                    List<String> patterns = texts(args.stream().filter(arg -> !(arg instanceof HttpMethodValue))
                            .toList()).orElse(List.of());
                    yield new MatcherValue(patterns.isEmpty() ? Matcher.custom("ServerWebExchangeMatcher")
                            : Matcher.paths(method, patterns));
                }
                default -> null;
            };
            case REACTIVE_PATH_REQUEST -> new StaticResources(List.of());
            case GRPC_REQUEST -> new GrpcServlet(Set.of());
            default -> null;
        };
    }

    /**
     * @param roles the role prefix in effect: the configured one for the DSL, {@code ROLE_} for managers built
     *        outside it
     */
    private Optional<Requirement> requirement(String name, List<DslValue> args, SpelRequirements roles) {
        return switch (name) {
            case "hasIpAddress" -> texts(args).map(addresses -> Requirement.expression("hasIpAddress("
                    + String.join(",", addresses) + ")"));
            case "access" -> args.isEmpty() ? Optional.empty() : Optional.of(access(args.getFirst()));
            default -> BuiltInManagers.named(name, managerArgs(args), roles);
        };
    }

    /**
     * {@code AuthorityAuthorizationManager.hasRole(..)}, {@code AuthorizationManagers.anyOf(..)} and the other
     * static factories, and the start of a {@code ConditionalAuthorizationManager}. Managers built this way have no
     * RoleHierarchy of their own.
     */
    private DslValue managerFactory(String owner, String name, List<String> parameterTypes, List<DslValue> args) {
        DslValue factors = multiFactor(owner, name, args);
        if (factors != null) {
            return factors;
        }
        if (owner.equals(AUTHORIZATION_PACKAGE + "ConditionalAuthorizationManager") && name.equals("when")) {
            return new Conditional();
        }
        return BuiltInManagers.factory(owner, name, parameterTypes, managerArgs(args)).map(Manager::new)
                .orElse(null);
    }

    /**
     * Decision 0063: what the built-in managers' table needs to know about the arguments.
     */
    private static List<BuiltInManagers.Arg> managerArgs(List<DslValue> args) {
        return args.stream().map(arg -> switch (arg) {
            case Text text -> new BuiltInManagers.Text(text.value());
            case Strings array when !array.managers().isEmpty() ->
                    new BuiltInManagers.Managers(array.managers(), array.unknown().isEmpty());
            case Strings array -> new BuiltInManagers.Texts(array.values(), array.unknown().isEmpty());
            case Manager manager -> new BuiltInManagers.Manager(manager.requirement());
            case NewObject created when created.type().equals(AUTHORIZATION_DECISION) && created.text() != null ->
                    new BuiltInManagers.Decision(created.text().equals("true"));
            case null, default -> BuiltInManagers.UNKNOWN;
        }).toList();
    }

    /**
     * Decision 0037: the multi-factor builders' static entry points.
     */
    @Supports(Feature.REQUIREMENTS)
    private static DslValue multiFactor(String owner, String name, List<DslValue> args) {
        return switch (owner) {
            case MultiFactor.FACTORIES -> name.equals("multiFactor")
                    ? new FactorsBuilder(FactorsBuilder.Kind.FACTORY) : null;
            case MultiFactor.ALL_FACTORS -> switch (name) {
                case "builder" -> new FactorsBuilder(FactorsBuilder.Kind.MANAGER);
                case "anyOf" -> {
                    List<Requirement> operands = args.stream().filter(Strings.class::isInstance)
                            .map(Strings.class::cast).flatMap(array -> array.managers().stream()).toList();
                    yield operands.isEmpty() ? null : new Manager(Requirement.or(operands));
                }
                default -> null;
            };
            case MultiFactor.REQUIRED_FACTOR -> {
                FactorsBuilder factor = new FactorsBuilder(FactorsBuilder.Kind.FACTOR);
                if (name.equals("withAuthority") && args.size() == 1 && args.getFirst() instanceof Text authority) {
                    factor.factors.authorities.add(authority.value());
                }
                yield name.equals("withAuthority") || name.equals("builder") ? factor : null;
            }
            default -> null;
        };
    }

    @Supports(Feature.REQUIREMENTS)
    private DslValue factorsCall(FactorsBuilder builder, String name, List<DslValue> args) {
        DslValue arg = args.isEmpty() ? null : args.getFirst();
        switch (name) {
            case "requireFactors", "requireFactor" -> {
                if (arg instanceof Strings authorities) {
                    builder.factors.authorities.addAll(authorities.values());
                }
                else if (arg instanceof Lambda lambda) {
                    builder.factors.add(MultiFactor.lambda(context, lambda.method()));
                }
                else if (arg instanceof MethodReference reference) {
                    MultiFactor.referenced(reference.method()).ifPresent(builder.factors.authorities::add);
                }
                else if (arg instanceof FactorsBuilder factor) {
                    builder.factors.add(factor.factors);
                }
            }
            case "when", "withWhen" -> builder.factors.conditions.add("a condition");
            case "authority" -> {
                if (arg instanceof Text authority) {
                    builder.factors.authorities.add(authority.value());
                }
            }
            case "validDuration" -> builder.factors.timed = true;
            case "build" -> {
                return switch (builder.kind) {
                    case FACTORY -> new FactoryValue(builder.factors.requirement());
                    case MANAGER -> new Manager(builder.factors.requirement());
                    case FACTOR -> builder;
                };
            }
            default -> MultiFactor.factorAuthority(name).ifPresent(builder.factors.authorities::add);
        }
        return builder;
    }

    /**
     * Decision 0018: a conditional admits at most the callers of either branch, so it is recorded as their
     * {@code or}, which is the weaker branch whenever the two can be ranked. An unset {@code whenFalse} is
     * {@code permitAll} (Spring Security 7.1.1's {@code Builder#build}).
     */
    private static Manager conditional(Conditional conditional) {
        Requirement whenTrue = conditional.whenTrue == null ? Requirement.expression("AuthorizationManager")
                : conditional.whenTrue;
        Requirement whenFalse = conditional.whenFalse == null ? Requirement.permitAll() : conditional.whenFalse;
        return new Manager(Requirement.or(List.of(whenTrue, whenFalse)).withSource("ConditionalAuthorizationManager"
                + " (whenTrue " + HttpSecurityRules.describe(whenTrue) + ", whenFalse "
                + HttpSecurityRules.describe(whenFalse) + ")"));
    }

    private Requirement access(DslValue manager) {
        if (manager instanceof Manager built) {
            return built.requirement();
        }
        if (manager instanceof NewObject created && created.type().equals(WEB_EXPRESSION_MANAGER)
                && created.text() != null) {
            return DEFAULT_ROLES.parse(created.text());
        }
        return customManager(manager).orElseGet(() -> Requirement.expression("access(" + (manager instanceof NewObject
                created ? created.type() : "AuthorizationManager") + ")"));
    }

    private static Optional<List<String>> texts(List<DslValue> args) {
        List<String> texts = new ArrayList<>();
        for (DslValue arg : args) {
            if (arg instanceof Text text) {
                texts.add(text.value());
            }
            else if (arg instanceof Strings strings) {
                texts.addAll(strings.values());
            }
            else {
                return Optional.empty();
            }
        }
        return texts.isEmpty() ? Optional.empty() : Optional.of(texts);
    }

    private static DslValue argument(Immediate argument, Map<Local, DslValue> values) {
        if (argument instanceof StringConstant constant) {
            return new Text(constant.getValue());
        }
        if (argument instanceof IntConstant constant) {
            return new Number(constant.getValue());
        }
        return argument instanceof Local local ? values.get(local) : null;
    }

    /**
     * Endpoint ids, or endpoint classes ({@code HealthEndpoint.class}) by their {@code @Endpoint} id.
     */
    private Set<String> endpointIds(List<DslValue> args) {
        ActuatorEndpoints actuator = new ActuatorEndpoints(context);
        Set<String> ids = new HashSet<>();
        texts(args).orElse(List.of()).forEach(text -> {
            if (text.startsWith(CLASS_LITERAL)) {
                actuator.id(text.substring(CLASS_LITERAL.length())).ifPresent(ids::add);
            }
            else {
                ids.add(text);
            }
        });
        return ids;
    }

    private static Optional<String> text(Value value, Map<Local, DslValue> values) {
        if (value instanceof StringConstant constant) {
            return Optional.of(constant.getValue());
        }
        if (value instanceof ClassConstant type) {
            return Optional.of(CLASS_LITERAL + type.getValue().replaceAll("^L|;$", "").replace('/', '.'));
        }
        return value instanceof Local local && values.get(local) instanceof Text text ? Optional.of(text.value())
                : Optional.empty();
    }
}
