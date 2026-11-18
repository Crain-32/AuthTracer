package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Registration;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.ConfigurationProperties;
import dev.crain.authtracer.scan.EnclosingMethods;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.IntConstant;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewExpr;
import sootup.core.jimple.common.ref.JArrayRef;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * What an Egress authenticates with (OAUTH-05, RX-11, SRC-16, SRC-17), read where its client is built.
 * <ul>
 * <li>{@code ServletBearerExchangeFilterFunction}/{@code ServerBearerExchangeFilterFunction}, or an application
 * interceptor or filter that sets {@code Authorization} from the security context or the incoming request: the
 * caller's token is relayed.</li>
 * <li>{@code OAuth2ClientHttpRequestInterceptor}, the authorized-client filter functions and OAuth2 group configurers:
 * a token from the OAuth2 client registration the request names.</li>
 * <li>Basic authentication helpers or a fixed {@code Authorization} header: static credentials.</li>
 * </ul>
 * Decision 0083: a {@code RestClient}, {@code WebClient} or {@code RestTemplate} call has the credentials of the
 * client it is made on, where that client is built: a client the class builds from a static factory
 * ({@code RestClient.create(..)}, {@code new RestTemplate()}) has only what is set there; one built from Boot's builder
 * also what Boot's customizers set (Boot 4.1.1 applies the {@code RestClientCustomizer}s, {@code WebClientCustomizer}s
 * and {@code RestTemplateCustomizer}s to its builder beans only); an injected client what its bean sets. HTTP service
 * groups get their group configurers and Boot's customizers (Boot's {@code RestClientCustomizerHttpServiceGroupConfigurer}),
 * and no other client does. Of the clients one method builds, each has what is set on it; an {@code Authorization}
 * value is followed back to where it comes from (decision 0083 amended).
 */
@Supports(Feature.CALL_CREDENTIALS)
final class EgressCredentials {

    /**
     * @param via what showed it, e.g. {@code ServletBearerExchangeFilterFunction}
     * @param perRequest whether it is an OAuth2 token only for a request that names its client registration: Spring
     *        Security's interceptor and filter functions resolve one from the request's attributes, and add nothing
     *        when there is none (7.1.1)
     * @param otherwise for a per-request token, what the client sends when the request names no registration: the
     *        strongest of the rest
     * @param registration the OAuth2 client registration whose own token it is, when AuthTracer reads which one
     */
    record Found(Credentials credentials, String via, boolean perRequest, Found otherwise, String registration) {
        static final Found NONE = new Found(Credentials.NONE, null);

        Found(Credentials credentials, String via) {
            this(credentials, via, false, null);
        }

        Found(Credentials credentials, String via, boolean perRequest, Found otherwise) {
            this(credentials, via, perRequest, otherwise, null);
        }

        /**
         * An OAuth2 client's own token, from the registration named.
         */
        static Found client(String via, String registration) {
            return new Found(Credentials.OAUTH2_CLIENT, via, false, null, registration);
        }

        /**
         * What a request that names no client registration is sent with.
         */
        Found unnamed(String why) {
            if (!perRequest) {
                return this;
            }
            return otherwise != null && otherwise.credentials() != Credentials.NONE ? otherwise
                    : new Found(Credentials.NONE, via + ", but " + why);
        }
    }

    private static final String RESOURCE_SERVER = "org.springframework.security.oauth2.server.resource.web.reactive"
            + ".function.client.";
    private static final String OAUTH2_CLIENT = "org.springframework.security.oauth2.client.";
    private static final String GRPC_SECURITY = "org.springframework.grpc.client.interceptor.security.";
    private static final String GRPC_BEARER = GRPC_SECURITY + "BearerTokenAuthenticationInterceptor";
    private static final String OAUTH2_INTERCEPTOR = OAUTH2_CLIENT + "web.client.OAuth2ClientHttpRequestInterceptor";
    private static final String OAUTH2_REST_GROUPS = OAUTH2_CLIENT
            + "web.client.support.OAuth2RestClientHttpServiceGroupConfigurer";
    private static final String OAUTH2_WEB_GROUPS = OAUTH2_CLIENT
            + "web.reactive.function.client.support.OAuth2WebClientHttpServiceGroupConfigurer";
    private static final String SERVLET_OAUTH2_FILTER = OAUTH2_CLIENT
            + "web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction";
    private static final String SERVER_OAUTH2_FILTER = OAUTH2_CLIENT
            + "web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction";
    private static final String FEIGN_BASIC_AUTH = "feign.auth.BasicAuthRequestInterceptor";
    private static final String FEIGN_OAUTH2 = "org.springframework.cloud.openfeign.security.OAuth2AccessTokenInterceptor";
    /**
     * Feign's and Spring Cloud OpenFeign's own interceptors (the latter gets the token of one registration).
     */
    private static final Map<String, Credentials> FEIGN_KNOWN = Map.of(FEIGN_BASIC_AUTH, Credentials.STATIC,
            FEIGN_OAUTH2, Credentials.OAUTH2_CLIENT);
    /**
     * A Feign {@code RequestInterceptor} bean's type: the interface, or one of {@link #FEIGN_KNOWN}.
     */
    private static final Set<String> FEIGN_INTERCEPTORS = Set.of("feign.RequestInterceptor", FEIGN_BASIC_AUTH,
            FEIGN_OAUTH2);
    private static final Map<String, Credentials> KNOWN = Map.ofEntries(
            Map.entry(RESOURCE_SERVER + "ServletBearerExchangeFilterFunction", Credentials.RELAY),
            Map.entry(RESOURCE_SERVER + "ServerBearerExchangeFilterFunction", Credentials.RELAY),
            Map.entry(OAUTH2_INTERCEPTOR, Credentials.OAUTH2_CLIENT),
            Map.entry(SERVLET_OAUTH2_FILTER, Credentials.OAUTH2_CLIENT),
            Map.entry(SERVER_OAUTH2_FILTER, Credentials.OAUTH2_CLIENT),
            Map.entry(OAUTH2_REST_GROUPS, Credentials.OAUTH2_CLIENT),
            Map.entry(OAUTH2_WEB_GROUPS, Credentials.OAUTH2_CLIENT),
            Map.entry("org.springframework.http.client.support.BasicAuthenticationInterceptor", Credentials.STATIC),
            // Spring gRPC's client interceptors and token suppliers (decision 0032).
            Map.entry(GRPC_SECURITY + "TokenRelayTokenSupplier", Credentials.RELAY),
            Map.entry(GRPC_SECURITY + "ClientCredentialsTokenSupplier", Credentials.OAUTH2_CLIENT),
            Map.entry(GRPC_SECURITY + "BasicAuthenticationInterceptor", Credentials.STATIC));
    /**
     * The OAuth2 interceptor, filter functions and group configurers (whose interceptor reads the
     * {@code @ClientRegistrationId} of the interface method): a token for the registration a request names.
     */
    private static final Set<String> PER_REQUEST = Set.of(OAUTH2_INTERCEPTOR, SERVLET_OAUTH2_FILTER,
            SERVER_OAUTH2_FILTER, OAUTH2_REST_GROUPS, OAUTH2_WEB_GROUPS);
    private static final Set<String> INTERCEPTORS = Set.of("org.springframework.http.client.ClientHttpRequestInterceptor",
            "org.springframework.web.reactive.function.client.ExchangeFilterFunction");
    private static final String WEB_CLIENT = "org.springframework.web.reactive.function.client.WebClient";
    private static final String REST_TEMPLATE = "org.springframework.web.client.RestTemplate";
    private static final String REST_TEMPLATE_BUILDER = "org.springframework.boot.restclient.RestTemplateBuilder";

    /**
     * A kind of client: its type, the builder type Boot gives the application, the customizers Boot applies to that
     * builder, and the configurers of HTTP service groups on it.
     */
    private record Kind(String client, String builder, String customizer, String groupConfigurer) {
    }

    private static final Kind REST_CLIENT_KIND = new Kind(SpringNames.REST_CLIENT, SpringNames.REST_CLIENT_BUILDER,
            "org.springframework.boot.restclient.RestClientCustomizer",
            "org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer");
    private static final Kind WEB_CLIENT_KIND = new Kind(WEB_CLIENT, WEB_CLIENT + "$Builder",
            "org.springframework.boot.webclient.WebClientCustomizer",
            "org.springframework.web.reactive.function.client.support.WebClientHttpServiceGroupConfigurer");
    private static final List<Kind> KINDS = List.of(REST_CLIENT_KIND, WEB_CLIENT_KIND, new Kind(REST_TEMPLATE,
            REST_TEMPLATE_BUILDER, "org.springframework.boot.restclient.RestTemplateCustomizer", null));
    private static final String GROUP_CONFIGURER = "org.springframework.web.service.registry.HttpServiceGroupConfigurer";
    /**
     * Beans whose code configures clients built elsewhere.
     */
    private static final Set<String> CONFIGURERS = Set.of(REST_CLIENT_KIND.customizer(), WEB_CLIENT_KIND.customizer(),
            KINDS.getLast().customizer(), REST_CLIENT_KIND.groupConfigurer(), WEB_CLIENT_KIND.groupConfigurer(),
            GROUP_CONFIGURER);
    private static final Set<String> GROUP_CONFIGURERS = Set.of(REST_CLIENT_KIND.groupConfigurer(),
            WEB_CLIENT_KIND.groupConfigurer(), GROUP_CONFIGURER, OAUTH2_REST_GROUPS, OAUTH2_WEB_GROUPS);
    private static final Set<String> CLIENTS = Set.of(SpringNames.REST_CLIENT, SpringNames.REST_CLIENT_BUILDER,
            WEB_CLIENT, WEB_CLIENT + "$Builder", REST_TEMPLATE, REST_TEMPLATE_BUILDER,
            "org.springframework.graphql.client.GraphQlClient", "org.springframework.graphql.client.WebGraphQlClient",
            "org.springframework.graphql.client.HttpGraphQlClient",
            "org.springframework.graphql.client.HttpSyncGraphQlClient");
    private static final String CLIENT_REGISTRATION_ID = OAUTH2_CLIENT + "annotation.ClientRegistrationId";
    private static final String REGISTRATION_ID_PROCESSOR = OAUTH2_CLIENT + "web.client.ClientRegistrationIdProcessor";
    private static final String FEIGN_INTERCEPTOR = "feign.RequestInterceptor";
    private static final String FEIGN_CLIENT = "org.springframework.cloud.openfeign.FeignClient";
    private static final Set<String> SECURITY_CONTEXT = Set.of(
            "org.springframework.security.core.context.SecurityContextHolder",
            "org.springframework.security.core.context.ReactiveSecurityContextHolder");
    private static final Set<String> AUTHORIZED_CLIENT_MANAGERS = Set.of(
            OAUTH2_CLIENT + "OAuth2AuthorizedClientManager", OAUTH2_CLIENT + "ReactiveOAuth2AuthorizedClientManager");
    private static final int MAX_CHAIN = 12;
    private static final String CLIENT_REGISTRATIONS = "spring.security.oauth2.client.registration.";
    /**
     * Grants whose token is issued for the signed-in user, so the called service checks the user, as on a relay.
     */
    private static final Set<String> USER_GRANTS = Set.of("authorization_code",
            "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "urn:ietf:params:oauth:grant-type:device_code");
    /**
     * Spring Security 7.1.1 has no password grant: its {@code AuthorizationGrantType} and authorized client providers
     * left it out, so what a registration asking for one sends is not Spring's to say.
     */
    private static final String PASSWORD = "password";
    /**
     * Spring Security 7.1.1's {@code CommonOAuth2Provider}s, whose registrations are authorization code ones.
     */
    private static final Set<String> COMMON_PROVIDERS = Set.of("google", "github", "facebook", "x", "okta");
    private static final Set<String> SETS_AUTHORIZATION = Set.of("setBearerAuth", "setBasicAuth",
            "basicAuthentication");
    private static final Set<String> HEADER_SETTERS = Set.of("set", "add", "header", "defaultHeader", "put");
    private static final Set<String> HEADER_GETTERS = Set.of("getHeader", "getFirst", "get");
    /**
     * How many steps back a header's value is followed: a Reactor pipeline's token takes about twenty, through its
     * lambdas and operators.
     */
    private static final int TRACE_DEPTH = 32;

    /**
     * How the chain that builds a client starts.
     */
    private enum Origin {
        /**
         * A static factory or constructor: {@code RestClient.create(..)}, {@code WebClient.builder()},
         * {@code new RestTemplate()}.
         */
        OWN,
        /**
         * The builder Boot gives the application.
         */
        BOOT_BUILDER,
        /**
         * A client bean, given to the class.
         */
        INJECTED
    }

    /**
     * Where a client is built: the method, and how its chain starts.
     *
     * @param name the field or bean it is built into, which Spring falls back to when it picks among client beans
     * @param chain the locals of the chain that builds it, from the client back to where it starts
     */
    private record Build(JavaSootMethod method, Kind kind, Origin origin, String name, Set<Local> chain) {
    }

    private final ScanContext context;
    private final Map<String, Found> byClass = new ConcurrentHashMap<>();
    private final Map<String, Found> byClient = new ConcurrentHashMap<>();
    private final Map<String, Found> byFeignClient = new ConcurrentHashMap<>();
    private Set<String> feignConfigurations;
    private List<JavaSootMethod> shared;
    private Uses uses;
    private CallTraversal calls;
    private ConfiguredValues configured;
    private EnclosingMethods enclosing;

    EgressCredentials(ScanContext context) {
        this.context = context;
    }

    /**
     * Decision 0083: a call on a {@code RestClient}, {@code WebClient} or {@code RestTemplate}: the credentials set
     * where that client is built, when AuthTracer sees where (a field the class assigns, or a client built in the
     * method), else the class's ({@link #forClass}).
     *
     * @param client the client the call is made on
     */
    Found forClient(JavaSootMethod caller, Local client) {
        return byClient.computeIfAbsent(caller.getSignature() + " " + client.getName(), key -> {
            List<Build> builds = builds(caller, client);
            if (builds.isEmpty()) {
                return context.findClass(caller.getDeclaringClassType()).map(this::forClass).orElse(Found.NONE);
            }
            // A field two constructors assign: the strongest.
            return strongest(builds.stream().map(build -> forBuild(build, new HashSet<>())).toList());
        });
    }

    /**
     * The builds of the client a local holds: each assignment of the field it is read from, or the chain that makes
     * it in the method; none when one of them starts where AuthTracer can't see.
     */
    private List<Build> builds(JavaSootMethod caller, Local client) {
        if (!(Locals.definition(caller.getBody(), client).orElse(null) instanceof JFieldRef field)) {
            return build(caller, client, client.getName(), false).map(List::of).orElse(List.of());
        }
        Optional<JavaSootClass> owner = context.isApplication(field.getFieldSignature().getDeclClassType())
                ? context.findClass(field.getFieldSignature().getDeclClassType()) : Optional.empty();
        List<Build> builds = new ArrayList<>();
        for (JavaSootMethod method : owner.map(JavaSootClass::getMethods).orElse(Set.of())) {
            for (Stmt stmt : method.hasBody() ? method.getBody().getStmts() : List.<Stmt>of()) {
                if (stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof JFieldRef target
                        && target.getFieldSignature().equals(field.getFieldSignature())) {
                    Optional<Build> build = build(method, assign.getRightOp(), field.getFieldSignature().getName(),
                            true);
                    if (build.isEmpty()) {
                        return List.of();
                    }
                    builds.add(build.get());
                }
            }
        }
        return builds;
    }

    /**
     * Follows the chain that makes a client back to where it starts.
     *
     * @param intoField whether the client goes into a field, where a client given to the method is a bean injected
     */
    private Optional<Build> build(JavaSootMethod method, Value value, String name, boolean intoField) {
        Value current = value;
        Set<Local> chain = new HashSet<>();
        for (int depth = 0; depth < MAX_CHAIN && current instanceof Local local; depth++) {
            chain.add(local);
            Value definition = Locals.definition(method.getBody(), local).orElse(null);
            if (definition instanceof JCastExpr cast) {
                current = cast.getOp();
                continue;
            }
            if (definition instanceof JNewExpr created) {
                return kindOf(created.getType().getFullyQualifiedName())
                        .map(kind -> new Build(method, kind, Origin.OWN, name, chain));
            }
            if (definition instanceof JParameterRef || definition instanceof JFieldRef) {
                String type = local.getType().toString();
                Optional<Kind> builder = KINDS.stream().filter(kind -> kind.builder().equals(type)).findFirst();
                if (builder.isPresent()) {
                    return Optional.of(new Build(method, builder.get(), Origin.BOOT_BUILDER, name, chain));
                }
                return KINDS.stream().filter(kind -> intoField && kind.client().equals(type)).findFirst()
                        .map(kind -> new Build(method, kind, Origin.INJECTED, name, chain));
            }
            if (!(definition instanceof AbstractInvokeExpr call)) {
                return Optional.empty();
            }
            Optional<Kind> kind = kindOf(call.getMethodSignature().getDeclClassType().getFullyQualifiedName());
            if (kind.isEmpty()) {
                return Optional.empty();
            }
            if (!(call instanceof AbstractInstanceInvokeExpr instance)) {
                // RestClient.create(..), WebClient.builder(), ...
                return Optional.of(new Build(method, kind.get(), Origin.OWN, name, chain));
            }
            current = instance.getBase();
        }
        return Optional.empty();
    }

    /**
     * Decision 0083 amended: what a method that builds several clients sets on this one. These are the statements that
     * build it or act on it: its chain, the field it is built into read back, what an invoke on them returns other
     * than a client or builder (a {@code RestTemplate}'s {@code getInterceptors()}), and calls given it. Then what they use, followed back: the
     * interceptors, filters and lambdas passed in, with what is done to them ({@code setDefaultClientRegistrationId}).
     * A builder two chains share is in both, as Spring's builders are mutable. A method that builds one client keeps
     * all of its statements, as before.
     */
    private Map<JavaSootMethod, List<Stmt>> isolated(Build build) {
        JavaSootMethod method = build.method();
        List<Stmt> stmts = method.getBody().getStmts();
        long built = stmts.stream().filter(stmt -> stmt instanceof AbstractDefinitionStmt definition
                && definition.getLeftOp() instanceof Local local && (definition.getRightOp() instanceof JNewExpr
                        || definition.getRightOp() instanceof AbstractInvokeExpr)
                && KINDS.stream().anyMatch(kind -> kind.client().equals(local.getType().toString()))).count();
        if (built < 2) {
            return Map.of();
        }
        Set<Local> objects = new HashSet<>(build.chain());
        // The field it is built into, read back later in the method.
        Set<String> fields = new HashSet<>();
        for (Stmt stmt : stmts) {
            if (stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof JFieldRef field
                    && objects.contains(assign.getRightOp())) {
                fields.add(field.getFieldSignature().toString());
            }
            else if (stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof Local read
                    && assign.getRightOp() instanceof JFieldRef field
                    && fields.contains(field.getFieldSignature().toString())) {
                objects.add(read);
            }
            else if (stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof Local derived
                    && assign.getRightOp() instanceof AbstractInstanceInvokeExpr call
                    && objects.contains(call.getBase()) && kindOf(derived.getType().toString()).isEmpty()) {
                objects.add(derived);
            }
        }
        Set<Stmt> selected = new HashSet<>();
        java.util.Deque<Local> used = new java.util.ArrayDeque<>();
        for (Stmt stmt : stmts) {
            boolean defines = stmt.getDef().filter(objects::contains).isPresent();
            boolean acts = Locals.invoke(stmt).filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr instance
                    && objects.contains(instance.getBase()) || invoke.getArgs().stream().anyMatch(objects::contains))
                    .isPresent();
            if (defines || acts) {
                selected.add(stmt);
                stmt.getUses().stream().filter(Local.class::isInstance).map(Local.class::cast).forEach(used::add);
            }
        }
        Set<Local> seen = new HashSet<>(objects);
        // The class's own fields are read through it; following it would take in everything.
        if (!method.isStatic()) {
            seen.add(method.getBody().getThisLocal());
        }
        while (!used.isEmpty()) {
            Local local = used.pop();
            if (!seen.add(local)) {
                continue;
            }
            for (Stmt stmt : stmts) {
                boolean defines = stmt.getDef().filter(local::equals).isPresent();
                boolean acts = Locals.invoke(stmt).filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr
                        instance && instance.getBase().equals(local)).isPresent();
                if ((defines || acts) && selected.add(stmt)) {
                    stmt.getUses().stream().filter(Local.class::isInstance).map(Local.class::cast).forEach(used::add);
                }
            }
        }
        return Map.of(method, stmts.stream().filter(selected::contains).toList());
    }

    /**
     * The kind of client a client or builder type (or a spec of it) builds.
     */
    private static Optional<Kind> kindOf(String type) {
        return KINDS.stream().filter(kind -> type.equals(kind.client()) || type.equals(kind.builder())
                || type.startsWith(kind.client() + "$")).findFirst();
    }

    private Found forBuild(Build build, Set<JavaSootMethod> visited) {
        List<JavaSootMethod> methods = new ArrayList<>(List.of(build.method()));
        Map<JavaSootMethod, List<Stmt>> only = isolated(build);
        switch (build.origin()) {
            case OWN -> {
            }
            case BOOT_BUILDER -> {
                // A builder bean of the application's replaces Boot's, and Boot's customizers with it.
                List<JavaSootMethod> builders = SpringBeans.beanMethods(context, build.kind().builder());
                methods.addAll(builders.isEmpty() ? customizers(build.kind().customizer()) : builders);
            }
            case INJECTED -> {
                return injected(build, resolve(methods, only), visited);
            }
        }
        return resolve(methods, only);
    }

    /**
     * A client bean given to the class: the one named as its field, as Spring falls back to the name to pick among
     * several, else the only kind of credentials its beans have; what the class adds to it is its own.
     */
    private Found injected(Build build, Found own, Set<JavaSootMethod> visited) {
        List<JavaSootMethod> beans = SpringBeans.beanMethods(context, build.kind().client()).stream()
                .filter(bean -> !visited.contains(bean)).toList();
        List<JavaSootMethod> named = beans.stream().filter(bean -> beanName(bean).equals(build.name())).toList();
        List<JavaSootMethod> used = named.size() == 1 ? named : beans;
        visited.addAll(used);
        List<Found> found = used.stream().map(bean -> beanCredentials(bean, visited)).toList();
        Set<Credentials> kinds = found.stream().map(Found::credentials).collect(Collectors.toSet());
        if (kinds.size() > 1) {
            return own != Found.NONE ? own : new Found(Credentials.UNKNOWN, "one of several client beans");
        }
        List<Found> all = new ArrayList<>(found);
        all.add(own);
        return strongest(all);
    }

    /**
     * What a client bean authenticates with: the client it returns, where that is built.
     */
    private Found beanCredentials(JavaSootMethod bean, Set<JavaSootMethod> visited) {
        for (Stmt stmt : bean.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned) {
                Optional<Build> build = build(bean, returned.getOp(), bean.getName(), false);
                if (build.isPresent()) {
                    return forBuild(build.get(), visited);
                }
            }
        }
        return resolve(List.of(bean));
    }

    private String beanName(JavaSootMethod bean) {
        return context.findAnnotation(bean, SpringNames.BEAN).flatMap(annotation -> Annotations.string(annotation,
                "name").or(() -> Annotations.string(annotation, "value"))).filter(name -> !name.isEmpty())
                .orElse(bean.getName());
    }

    /**
     * The customizer classes and beans of a type: Boot applies them to every client its builder makes.
     */
    private List<JavaSootMethod> customizers(String type) {
        List<JavaSootMethod> methods = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            boolean customizer = context.interfacesOf(cls.getType()).stream()
                    .anyMatch(implemented -> implemented.getFullyQualifiedName().equals(type));
            for (JavaSootMethod method : cls.getMethods()) {
                if (customizer || context.hasAnnotation(method, SpringNames.BEAN)
                        && method.getReturnType().toString().equals(type)) {
                    methods.add(method);
                }
            }
        }
        return methods;
    }

    /**
     * The strongest of several: relay, then OAuth2 client, static, unknown; none when nothing sets credentials. Of
     * one strength, a token the client gets whatever the request is comes first; a per-request one keeps what the
     * others send without it.
     */
    private static Found strongest(List<Found> found) {
        Found best = pick(found);
        if (!best.perRequest()) {
            return best;
        }
        Found otherwise = pick(found.stream().map(candidate -> candidate.perRequest()
                ? Optional.ofNullable(candidate.otherwise()).orElse(Found.NONE) : candidate).toList());
        return new Found(best.credentials(), best.via(), true, otherwise, best.registration());
    }

    private static Found pick(List<Found> found) {
        for (Credentials credentials : List.of(Credentials.RELAY, Credentials.OAUTH2_CLIENT, Credentials.STATIC,
                Credentials.UNKNOWN)) {
            Optional<Found> match = found.stream().filter(candidate -> candidate.credentials() == credentials)
                    .min(Comparator.comparing(Found::perRequest));
            if (match.isPresent()) {
                return match.get();
            }
        }
        return Found.NONE;
    }

    /**
     * A call this class makes on a client AuthTracer doesn't see built, or on another kind of client.
     */
    Found forClass(JavaSootClass cls) {
        return byClass.computeIfAbsent(cls.getName(), name -> {
            List<JavaSootMethod> methods = new ArrayList<>(cls.getMethods());
            List<JavaSootMethod> beans = shared().stream().filter(method -> !configurer(method)
                    && !groupConfigurer(method) && !method.getDeclaringClassType().equals(cls.getType())).toList();
            methods.addAll(shared().stream().filter(this::configurer).toList());
            // The client bean the class is given: the one its client field is named after, as Spring falls back
            // to the name to pick among several, else the only kind of client the beans build. (The beans are
            // shared(): each returns a class type.)
            Map<String, String> fields = clientFields(cls);
            List<JavaSootMethod> typed = fields.isEmpty() ? beans : beans.stream()
                    .filter(bean -> !CLIENTS.contains(bean.getReturnType().toString())
                            || fields.containsValue(bean.getReturnType().toString()))
                    .toList();
            List<JavaSootMethod> named = typed.stream().filter(bean -> fields.containsKey(bean.getName())).toList();
            List<JavaSootMethod> used = named.size() == 1 ? named : typed;
            Set<Credentials> kinds = used.stream().map(bean -> resolve(List.of(bean)).credentials())
                    .collect(Collectors.toSet());
            Found own = resolve(methods);
            if (kinds.size() > 1 && own == Found.NONE) {
                return new Found(Credentials.UNKNOWN, "one of several client beans");
            }
            if (kinds.size() <= 1) {
                methods.addAll(used);
            }
            return resolve(methods);
        });
    }

    /**
     * A client customizer: it applies to every client the builders make.
     */
    private boolean configurer(JavaSootMethod method) {
        Set<String> customizers = KINDS.stream().map(Kind::customizer).collect(Collectors.toSet());
        return context.interfacesOf(method.getDeclaringClassType()).stream()
                .anyMatch(type -> customizers.contains(type.getFullyQualifiedName()))
                || customizers.contains(method.getReturnType().toString());
    }

    /**
     * An HTTP service group configurer: it applies to the groups' clients only.
     */
    private boolean groupConfigurer(JavaSootMethod method) {
        return context.interfacesOf(method.getDeclaringClassType()).stream()
                .anyMatch(type -> GROUP_CONFIGURERS.contains(type.getFullyQualifiedName()))
                || GROUP_CONFIGURERS.contains(method.getReturnType().toString());
    }

    /**
     * The class's fields that hold a client, by name, with their types.
     */
    private static Map<String, String> clientFields(JavaSootClass cls) {
        Map<String, String> fields = new java.util.HashMap<>();
        cls.getFields().stream().filter(field -> field.getType() instanceof ClassType type
                && CLIENTS.contains(type.getFullyQualifiedName()))
                .forEach(field -> fields.put(field.getName(), field.getType().toString()));
        return fields;
    }

    /**
     * Decision 0042: a call to an OpenFeign client: what its {@code RequestInterceptor}s (beans, the classes that
     * implement it, and the client's {@code configuration} classes) put in the {@code Authorization} header, or the
     * OAuth2 client token {@code spring.cloud.openfeign.oauth2.enabled} adds. A configuration class that isn't a
     * component is only in the contexts of the clients that list it, so its interceptors are theirs alone.
     */
    Found forFeign(JavaSootClass client, AnnotationUsage annotation) {
        return byFeignClient.computeIfAbsent(client.getName(), name -> {
            if (context.properties().flag("spring.cloud.openfeign.oauth2.enabled").orElse(false)) {
                return new Found(Credentials.OAUTH2_CLIENT, "spring.cloud.openfeign.oauth2");
            }
            List<String> configurations = Annotations.strings(annotation, "configuration");
            List<JavaSootMethod> methods = new ArrayList<>();
            for (JavaSootClass cls : context.applicationClasses()) {
                boolean interceptor = context.interfacesOf(cls.getType()).stream()
                        .anyMatch(type -> type.getFullyQualifiedName().equals(FEIGN_INTERCEPTOR));
                String className = cls.getType().getFullyQualifiedName();
                boolean othersOnly = !configurations.contains(className) && feignConfigurations().contains(className)
                        && !context.hasAnnotation(cls, SpringNames.COMPONENT);
                for (JavaSootMethod method : cls.getMethods()) {
                    if (!method.hasBody()) {
                        continue;
                    }
                    boolean bean = FEIGN_INTERCEPTORS.contains(method.getReturnType().toString()) && !othersOnly
                            && context.hasAnnotation(method, SpringNames.BEAN);
                    if (interceptor || bean) {
                        methods.addAll(withCallees(method));
                    }
                    // The interceptor lambda the bean returns, written there or in a helper it calls.
                    for (JavaSootMethod builder : bean ? withCallees(method) : List.<JavaSootMethod>of()) {
                        for (Stmt stmt : builder.getBody().getStmts()) {
                            if (stmt instanceof AbstractDefinitionStmt definition
                                    && definition.getRightOp() instanceof JDynamicInvokeExpr dynamic) {
                                lambda(dynamic).map(this::withCallees).ifPresent(methods::addAll);
                            }
                        }
                    }
                }
            }
            // An interceptor written there, or Feign's and Spring Cloud OpenFeign's own created there.
            List<Found> found = new ArrayList<>();
            classify(methods, "RequestInterceptor").ifPresent(found::add);
            for (JavaSootMethod method : methods) {
                for (Stmt stmt : method.getBody().getStmts()) {
                    if (stmt instanceof AbstractDefinitionStmt definition
                            && definition.getRightOp() instanceof JNewExpr created
                            && FEIGN_KNOWN.containsKey(created.getType().getFullyQualifiedName())) {
                        String type = created.getType().getFullyQualifiedName();
                        found.add(new Found(FEIGN_KNOWN.get(type), simpleName(type)));
                    }
                }
            }
            return strongest(found);
        });
    }

    /**
     * The classes any {@code @FeignClient} lists as its {@code configuration}.
     */
    private synchronized Set<String> feignConfigurations() {
        if (feignConfigurations == null) {
            feignConfigurations = context.applicationClasses().stream().filter(JavaSootClass::isInterface)
                    .flatMap(cls -> context.findAnnotation(cls, FEIGN_CLIENT).stream())
                    .flatMap(annotation -> Annotations.strings(annotation, "configuration").stream())
                    .collect(Collectors.toUnmodifiableSet());
        }
        return feignConfigurations;
    }

    /**
     * A call to an HTTP interface method: in an HTTP service group, what the group's configurers and Boot's
     * customizers set on its client; wired by hand, what the client it is wired on has; else what the code around
     * it sets, or its {@code @ClientRegistrationId}. An OAuth2 interceptor's token is the registration
     * {@code @ClientRegistrationId} names, which a group's OAuth2 configurer reads, and a hand-wired proxy factory with
     * {@code ClientRegistrationIdProcessor}.
     *
     * @param wiring the method that creates the client with {@code HttpServiceProxyFactory}, if there is one
     * @param group the client type of the interface's HTTP service group ({@code REST_CLIENT}, {@code WEB_CLIENT}),
     *        when it is in one
     */
    Found forHttpInterface(JavaSootClass service, JavaSootMethod method, Optional<JavaSootMethod> wiring,
            Optional<String> group) {
        Optional<String> registration = context.findAnnotation(method, CLIENT_REGISTRATION_ID)
                .or(() -> context.findAnnotation(service, CLIENT_REGISTRATION_ID))
                // value is an alias for registrationId.
                .map(annotation -> Annotations.string(annotation, "value").filter(id -> !id.isEmpty())
                        .or(() -> Annotations.string(annotation, "registrationId")).orElse(""));
        Found found;
        boolean readsRegistration;
        if (group.isPresent()) {
            Kind kind = group.get().equals("WEB_CLIENT") ? WEB_CLIENT_KIND : REST_CLIENT_KIND;
            List<JavaSootMethod> methods = new ArrayList<>(customizers(kind.customizer()));
            methods.addAll(groupConfigurers(kind));
            found = resolve(methods);
            readsRegistration = true;
        }
        else if (wiring.isPresent()) {
            found = adapted(wiring.get()).map(client -> forClient(wiring.get(), client)).orElseGet(() -> {
                List<JavaSootMethod> methods = new ArrayList<>(shared());
                methods.add(wiring.get());
                return resolve(methods);
            });
            readsRegistration = wiring.get().getBody().getStmts().stream()
                    .anyMatch(stmt -> stmt instanceof AbstractDefinitionStmt definition
                            && definition.getRightOp() instanceof JStaticFieldRef field && field.getFieldSignature()
                                    .getDeclClassType().getFullyQualifiedName().equals(REGISTRATION_ID_PROCESSOR));
        }
        else {
            // Created where AuthTracer doesn't see: what the interface declares.
            if (registration.isPresent()) {
                return forRegistration(registration.get(), "@ClientRegistrationId(\"" + registration.get() + "\")");
            }
            return resolve(shared().stream().filter(bean -> !groupConfigurer(bean)).toList());
        }
        if (!found.perRequest() && !(registration.isPresent() && found.credentials() == Credentials.OAUTH2_CLIENT)) {
            return found;
        }
        if (registration.isPresent() && readsRegistration) {
            return forRegistration(registration.get(), "@ClientRegistrationId(\"" + registration.get() + "\")");
        }
        return found.unnamed(registration.isEmpty() ? "the method names no @ClientRegistrationId"
                : "no ClientRegistrationIdProcessor reads its @ClientRegistrationId");
    }

    /**
     * The group configurer classes and beans of the kind of client, Spring Security's among them.
     */
    private List<JavaSootMethod> groupConfigurers(Kind kind) {
        Set<String> types = Set.of(kind.groupConfigurer(), GROUP_CONFIGURER, kind == WEB_CLIENT_KIND
                ? OAUTH2_WEB_GROUPS : OAUTH2_REST_GROUPS);
        List<JavaSootMethod> methods = new ArrayList<>();
        for (JavaSootClass cls : context.applicationClasses()) {
            boolean configurer = context.interfacesOf(cls.getType()).stream()
                    .anyMatch(implemented -> types.contains(implemented.getFullyQualifiedName()));
            for (JavaSootMethod method : cls.getMethods()) {
                if (configurer || context.hasAnnotation(method, SpringNames.BEAN)
                        && types.contains(method.getReturnType().toString())) {
                    methods.add(method);
                }
            }
        }
        return methods;
    }

    /**
     * The client a hand-wired proxy factory's adapter is made from: {@code RestClientAdapter.create(client)}, or the
     * WebClient's or RestTemplate's.
     */
    private Optional<Local> adapted(JavaSootMethod wiring) {
        return wiring.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                        .endsWith("Adapter") && invoke.getMethodSignature().getName().equals("create")
                        && invoke.getArgCount() == 1 && invoke.getArg(0) instanceof Local)
                .map(invoke -> (Local) invoke.getArg(0)).findFirst();
    }

    /**
     * An OAuth2 client registration's token, by its grant type: an authorization code (or token exchange, JWT bearer,
     * device code) token is issued for the signed-in user, so the called service checks the user, as on a relay; a
     * client credentials token is the service's own; a password grant's is unknown.
     */
    Found forRegistration(String registration, String via) {
        String grant = grant(registration);
        if (grant.equals(PASSWORD)) {
            return new Found(Credentials.UNKNOWN, via + ", a password grant, which Spring Security 7.1.1 has no"
                    + " provider for");
        }
        return USER_GRANTS.contains(grant) ? new Found(Credentials.RELAY, via + ", the signed-in user's " + grant
                + " token") : Found.client(via, registration);
    }

    /**
     * The grant type a client registration's properties name. Without one, Spring Boot 4.1.1's
     * {@code OAuth2ClientPropertiesMapper} builds the registration from its provider's issuer, or from a
     * {@code CommonOAuth2Provider} its provider (by default its id) names, both {@code authorization_code}; empty
     * otherwise.
     */
    private String grant(String registration) {
        String prefix = CLIENT_REGISTRATIONS + registration + ".";
        Optional<String> named = context.properties().get(prefix + "authorization-grant-type").map(String::trim);
        if (named.isPresent() || !context.properties().hasPrefix(prefix)) {
            return named.orElse("");
        }
        String provider = context.properties().get(prefix + "provider").map(String::trim).orElse(registration);
        boolean issuer = context.properties().get("spring.security.oauth2.client.provider." + provider
                + ".issuer-uri").isPresent();
        return issuer || COMMON_PROVIDERS.contains(provider.toLowerCase(java.util.Locale.ROOT).replace("-", ""))
                ? "authorization_code" : "";
    }

    /**
     * Decision 0075 amended: the client registration an OAuth2 client's own token is issued to, as the service's
     * properties declare it ({@code spring.security.oauth2.client.registration.<id>}): the client it authenticates
     * as, its grant type, the scopes it asks for, and its provider's token endpoint or issuer. Empty when no
     * registration is named or the properties declare none of that name (one a bean builds in code).
     */
    @Supports(Feature.FINDING_TOKEN_REJECTED)
    Optional<Registration> registration(Found found) {
        if (found.credentials() != Credentials.OAUTH2_CLIENT || found.registration() == null) {
            return Optional.empty();
        }
        String id = found.registration();
        String prefix = CLIENT_REGISTRATIONS + id + ".";
        ConfigurationProperties properties = context.properties();
        if (!properties.hasPrefix(prefix)) {
            return Optional.empty();
        }
        // A registration's provider defaults to one of its own id.
        String provider = "spring.security.oauth2.client.provider." + properties.get(prefix + "provider").orElse(id)
                + ".";
        return Optional.of(new Registration(id, properties.get(prefix + "client-id").orElse(null),
                Optional.of(grant(id)).filter(grant -> !grant.isEmpty()).orElse(null),
                new java.util.TreeSet<>(properties.list(prefix + "scope")),
                properties.get(provider + "token-uri").orElse(null),
                properties.get(provider + "issuer-uri").orElse(null)));
    }

    /**
     * The registration a method's requests name, when they all name the same one: {@code clientRegistrationId("x")}
     * (RestClient's request attribute, or WebClient's exchange filter function's).
     */
    Optional<String> registrationIn(JavaSootMethod method) {
        // The method a call is made in: it has a body.
        Set<String> registrations = new java.util.HashSet<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            Locals.invoke(stmt).filter(invoke -> invoke.getMethodSignature().getName().equals("clientRegistrationId")
                    && invoke.getArgCount() == 1 && invoke.getArg(0) instanceof StringConstant)
                    .ifPresent(invoke -> registrations.add(((StringConstant) invoke.getArg(0)).getValue()));
        }
        return registrations.size() == 1 ? registrations.stream().findFirst() : Optional.empty();
    }

    /**
     * An authorized client a method's requests carry: the filter functions'
     * {@code .attributes(oauth2AuthorizedClient(client))}, whose token they send as it is.
     */
    Optional<Found> authorizedClientIn(JavaSootMethod method) {
        return method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> invoke.getMethodSignature().getName().equals("oauth2AuthorizedClient")
                        && Set.of(SERVLET_OAUTH2_FILTER, SERVER_OAUTH2_FILTER).contains(invoke.getMethodSignature()
                                .getDeclClassType().getFullyQualifiedName()))
                .findFirst().map(invoke -> new Found(Credentials.OAUTH2_CLIENT, "oauth2AuthorizedClient(..)"));
    }

    /**
     * Client customizer and group configurer beans (and classes implementing them), and beans that build clients.
     */
    private List<JavaSootMethod> shared() {
        if (shared == null) {
            shared = new ArrayList<>();
            for (JavaSootClass cls : context.applicationClasses()) {
                boolean configurer = context.interfacesOf(cls.getType()).stream()
                        .anyMatch(type -> CONFIGURERS.contains(type.getFullyQualifiedName()));
                for (JavaSootMethod method : cls.getMethods()) {
                    String returned = method.getReturnType().toString();
                    if (configurer || context.hasAnnotation(method, SpringNames.BEAN) && (CONFIGURERS.contains(returned)
                            || CLIENTS.contains(returned) || KNOWN.containsKey(returned))) {
                        shared.add(method);
                    }
                }
            }
        }
        return shared;
    }

    /**
     * The strongest signal wins: relay, then OAuth2 client, static, unknown; none when nothing sets credentials.
     */
    private Found resolve(List<JavaSootMethod> methods) {
        return resolve(methods, Map.of());
    }

    /**
     * @param only the statements to read of a method, when not all of them ({@link #isolated})
     */
    private Found resolve(List<JavaSootMethod> methods, Map<JavaSootMethod, List<Stmt>> only) {
        Set<Found> found = new LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        // A stable order, so the same code always reports the same "via".
        for (JavaSootMethod method : methods.stream()
                .sorted(Comparator.comparing(method -> method.getSignature().toString())).toList()) {
            scan(method, only.get(method), 2, found, seen);
        }
        return strongest(List.copyOf(found));
    }

    private void scan(JavaSootMethod method, int depth, Set<Found> found, Set<String> seen) {
        scan(method, null, depth, found, seen);
    }

    /**
     * Interceptors and filters created here, lambdas defined here (configurer callbacks), and credentials this
     * method sets itself.
     *
     * @param only the statements to read, {@code null} for all of them
     */
    private void scan(JavaSootMethod method, List<Stmt> only, int depth, Set<Found> found, Set<String> seen) {
        if (!method.hasBody() || !seen.add(method.getSignature().toString())) {
            return;
        }
        List<Stmt> stmts = only != null ? only : method.getBody().getStmts();
        classify(Map.of(method, stmts), simpleName(method.getDeclaringClassType().getFullyQualifiedName()))
                .ifPresent(found::add);
        for (Stmt stmt : stmts) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getRightOp() instanceof JNewExpr created) {
                interceptorClass(created.getType()).ifPresent(found::add);
                if (created.getType().getFullyQualifiedName().equals(GRPC_BEARER)
                        && definition.getLeftOp() instanceof Local interceptor) {
                    grpcBearer(method, interceptor).ifPresent(found::add);
                }
            }
            if (stmt instanceof AbstractDefinitionStmt definition
                    && definition.getRightOp() instanceof JDynamicInvokeExpr dynamic) {
                lambda(dynamic).ifPresent(target -> {
                    if (INTERCEPTORS.contains(dynamic.getType().toString())) {
                        classify(withCallees(target), "interceptor lambda in " + simpleName(method
                                .getDeclaringClassType().getFullyQualifiedName())).ifPresent(found::add);
                    }
                    else if (depth > 0) {
                        scan(target, depth - 1, found, seen);
                    }
                });
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent()) {
                String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                if (KNOWN.containsKey(owner)) {
                    found.add(known(owner));
                    defaultRegistration(owner, invoke.get()).ifPresent(found::add);
                }
            }
        }
    }

    private static Found known(String type) {
        return new Found(KNOWN.get(type), simpleName(type), PER_REQUEST.contains(type), null);
    }

    /**
     * Spring gRPC's {@code BearerTokenAuthenticationInterceptor} sends the token it is given: a {@code TokenSupplier}'s
     * (Spring gRPC's are {@link #KNOWN}; an application's is read from its code, where it is created), or a token or
     * a {@code Supplier<String>} of one, followed back to where it comes from (decision 0083 amended): the caller's
     * from the security context (a reactive client's from {@code ReactiveSecurityContextHolder}), an OAuth2 client's
     * from an authorized-client manager, a fixed one, or one AuthTracer can't follow.
     */
    private Optional<Found> grpcBearer(JavaSootMethod method, Local interceptor) {
        Optional<AbstractInvokeExpr> constructor = method.getBody().getStmts().stream()
                .flatMap(stmt -> Locals.invoke(stmt).stream())
                .filter(invoke -> invoke instanceof AbstractInstanceInvokeExpr instance
                        && instance.getBase().equals(interceptor) && invoke.getMethodSignature().getName().equals("<init>")
                        && invoke.getArgCount() == 1)
                .findFirst();
        if (constructor.isEmpty()) {
            return Optional.empty();
        }
        String via = simpleName(GRPC_BEARER);
        Value token = constructor.get().getArg(0);
        String parameter = constructor.get().getMethodSignature().getParameterTypes().getFirst().toString();
        if (parameter.equals(GRPC_SECURITY + "TokenSupplier")) {
            // A supplier the code creates here is read as it is created (KNOWN, or interceptorClass).
            return token instanceof Local supplier ? Locals.created(method.getBody(), supplier)
                    .flatMap(this::interceptorClass) : Optional.empty();
        }
        return Optional.of(found(via, trace(method, token, TRACE_DEPTH, new java.util.HashMap<>())));
    }

    /**
     * Decision 0032 amended: a call on a gRPC stub has what the interceptors on that stub send: those its chain adds
     * with {@code withInterceptors(..)}, where the call is made or where the field it is read from is assigned, so two
     * calls on one stub, each with its own interceptor, each have their own. A stub whose chain adds none has what the
     * class sets ({@link #forClass}).
     *
     * @param stub the stub the call is made on
     */
    Found forStub(JavaSootMethod caller, Local stub) {
        List<Found> found = new ArrayList<>();
        stubInterceptors(caller, stub, new HashSet<>(), found);
        return found.isEmpty() ? context.findClass(caller.getDeclaringClassType()).map(this::forClass)
                .orElse(Found.NONE) : strongest(found);
    }

    /**
     * Follows the chain that makes a stub back to where it starts, adding what each interceptor on it sends.
     */
    private void stubInterceptors(JavaSootMethod method, Value value, Set<String> seen, List<Found> found) {
        Value current = value;
        for (int depth = 0; depth < MAX_CHAIN && current instanceof Local local; depth++) {
            Value definition = Locals.definition(method.getBody(), local).orElse(null);
            if (definition instanceof JCastExpr cast) {
                current = cast.getOp();
                continue;
            }
            if (definition instanceof JFieldRef field) {
                if (seen.add(field.getFieldSignature().toString())) {
                    for (Map.Entry<JavaSootMethod, Value> write : uses().writes().getOrDefault(
                            field.getFieldSignature().toString(), List.of())) {
                        stubInterceptors(write.getKey(), write.getValue(), seen, found);
                    }
                }
                return;
            }
            // Where it starts: XGrpc.newStub(channel), a parameter, a bean.
            if (!(definition instanceof AbstractInstanceInvokeExpr call)) {
                return;
            }
            if (call.getMethodSignature().getName().equals("withInterceptors")) {
                for (Value argument : call.getArgs()) {
                    interceptorsIn(method, argument).forEach(found::add);
                }
            }
            current = call.getBase();
        }
    }

    /**
     * What the interceptors passed as one argument send: an array of them, as a varargs call passes them, each one
     * the method creates.
     */
    private List<Found> interceptorsIn(JavaSootMethod method, Value argument) {
        List<Local> created = new ArrayList<>();
        if (argument instanceof Local array) {
            for (Stmt stmt : method.getBody().getStmts()) {
                if (stmt instanceof AbstractDefinitionStmt definition
                        && definition.getLeftOp() instanceof JArrayRef element && element.getBase().equals(array)
                        && definition.getRightOp() instanceof Local stored) {
                    created.add(stored);
                }
            }
        }
        List<Found> found = new ArrayList<>();
        for (Local interceptor : created) {
            Optional<ClassType> type = Locals.created(method.getBody(), interceptor);
            if (type.isEmpty()) {
                continue;
            }
            (type.get().getFullyQualifiedName().equals(GRPC_BEARER) ? grpcBearer(method, interceptor)
                    : interceptorClass(type.get())).ifPresent(found::add);
        }
        return found;
    }

    /**
     * An OAuth2 interceptor or filter function told which registration to use when a request names none:
     * {@code setDefaultClientRegistrationId("x")}, {@code setDefaultOAuth2AuthorizedClient(true)} (the signed-in
     * user's), or a {@code ClientRegistrationIdResolver} of the application's.
     */
    private Optional<Found> defaultRegistration(String owner, AbstractInvokeExpr invoke) {
        String name = invoke.getMethodSignature().getName();
        String via = simpleName(owner) + "." + name;
        if (name.equals("setDefaultClientRegistrationId") && invoke.getArg(0) instanceof StringConstant id) {
            return Optional.of(forRegistration(id.getValue(), via + "(\"" + id.getValue() + "\")"));
        }
        if (name.equals("setDefaultOAuth2AuthorizedClient") && invoke.getArg(0) instanceof IntConstant flag
                && flag.getValue() == 1) {
            return Optional.of(new Found(Credentials.RELAY, via + ": the signed-in user's OAuth2 client"));
        }
        if (name.equals("setClientRegistrationIdResolver") || name.equals("setDefaultClientRegistrationId")) {
            return Optional.of(new Found(Credentials.OAUTH2_CLIENT, via));
        }
        return Optional.empty();
    }

    /**
     * {@code new X()}: a known filter or interceptor, an application one (read from its code), or another library one
     * AuthTracer can't read.
     */
    private Optional<Found> interceptorClass(ClassType type) {
        String name = type.getFullyQualifiedName();
        if (KNOWN.containsKey(name)) {
            return Optional.of(known(name));
        }
        boolean tokenSupplier = context.interfacesOf(type).stream()
                .anyMatch(implemented -> implemented.getFullyQualifiedName().equals(GRPC_SECURITY + "TokenSupplier"));
        if (tokenSupplier && context.isApplication(type)) {
            // Spring gRPC's bearer interceptor sends whatever token the supplier returns.
            return context.findClass(type).map(cls -> {
                Reads reads = reads(cls.getMethods().stream().filter(JavaSootMethod::hasBody)
                        .flatMap(method -> withCallees(method).stream()).toList());
                return new Found(reads.authorizedClient() ? Credentials.OAUTH2_CLIENT
                        : reads.caller() ? Credentials.RELAY : Credentials.UNKNOWN, simpleName(name));
            });
        }
        boolean interceptor = context.interfacesOf(type).stream()
                .anyMatch(implemented -> INTERCEPTORS.contains(implemented.getFullyQualifiedName()));
        if (!interceptor) {
            return Optional.empty();
        }
        if (!context.isApplication(type)) {
            return Optional.of(new Found(Credentials.UNKNOWN, simpleName(name)));
        }
        return context.findClass(type).flatMap(cls -> classify(cls.getMethods().stream().toList(), simpleName(name)));
    }

    private Optional<JavaSootMethod> lambda(JDynamicInvokeExpr dynamic) {
        for (Value argument : dynamic.getBootstrapArgs()) {
            if (argument instanceof MethodHandle handle && handle.getReferenceSignature() instanceof MethodSignature target
                    && context.isApplication(target.getDeclClassType())) {
                return context.findMethod(target).filter(JavaSootMethod::hasBody);
            }
        }
        return Optional.empty();
    }

    /**
     * A method and the application methods it calls directly, e.g. an interceptor and its token helper.
     */
    private List<JavaSootMethod> withCallees(JavaSootMethod method) {
        List<JavaSootMethod> methods = new ArrayList<>(List.of(method));
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            invoke.filter(call -> context.isApplication(call.getMethodSignature().getDeclClassType()))
                    .flatMap(call -> context.findMethod(call.getMethodSignature())).filter(JavaSootMethod::hasBody)
                    .ifPresent(methods::add);
        }
        return methods;
    }

    private Optional<Found> classify(List<JavaSootMethod> methods, String via) {
        return classify(code(methods), via);
    }

    /**
     * Every statement of the methods.
     */
    private static Map<JavaSootMethod, List<Stmt>> code(List<JavaSootMethod> methods) {
        Map<JavaSootMethod, List<Stmt>> code = new java.util.LinkedHashMap<>();
        methods.stream().filter(JavaSootMethod::hasBody).forEach(method -> code.putIfAbsent(method,
                method.getBody().getStmts()));
        return code;
    }

    /**
     * Code that sets an {@code Authorization} header: from an authorized-client manager it is an OAuth2 client token,
     * from the security context or the incoming request it relays. Otherwise (decision 0083 amended) the value it sets
     * is followed back ({@link #trace}) to the caller's token, an authorized client's, a fixed value, or a place
     * AuthTracer can't follow, which makes it UNKNOWN and says where.
     */
    private Optional<Found> classify(Map<JavaSootMethod, List<Stmt>> code, String via) {
        Reads reads = reads(code);
        if (!reads.setsAuthorization()) {
            return Optional.empty();
        }
        // An authorized-client manager may read the caller too (to authorize on their behalf); its token is its own.
        if (reads.authorizedClient() || reads.caller()) {
            return Optional.of(new Found(reads.authorizedClient() ? Credentials.OAUTH2_CLIENT : Credentials.RELAY,
                    via));
        }
        Traced traced = Traced.FIXED;
        Map<String, Traced> seen = new java.util.HashMap<>();
        for (Map.Entry<JavaSootMethod, List<Stmt>> method : code.entrySet()) {
            for (Stmt stmt : method.getValue()) {
                for (Value value : headerValues(stmt)) {
                    traced = traced.or(trace(method.getKey(), value, TRACE_DEPTH, seen));
                }
            }
        }
        return Optional.of(found(via, traced));
    }

    /**
     * What a value followed back to its source sends.
     */
    private static Found found(String via, Traced traced) {
        return switch (traced.source()) {
            case CLIENT -> Found.client(via + ": an authorized client's token, from " + traced.where(),
                    traced.registration());
            case CALLER -> new Found(Credentials.RELAY, via + ": the caller's token, from " + traced.where());
            case UNKNOWN -> new Found(Credentials.UNKNOWN, via + ": the Authorization value comes from "
                    + traced.where() + ", which AuthTracer can't follow");
            case FIXED -> new Found(Credentials.STATIC, via);
        };
    }

    /**
     * What code does with credentials: sets an {@code Authorization} header, reads the caller (the security context,
     * a token's value, the incoming request's header), or asks an authorized-client manager for a token.
     */
    private record Reads(boolean setsAuthorization, boolean caller, boolean authorizedClient) {
    }

    private static Reads reads(List<JavaSootMethod> methods) {
        return reads(code(methods));
    }

    private static Reads reads(Map<JavaSootMethod, List<Stmt>> code) {
        boolean setsAuthorization = false;
        boolean readsCaller = false;
        boolean authorizedClient = false;
        for (List<Stmt> stmts : code.values()) {
            for (Stmt stmt : stmts) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty()) {
                    continue;
                }
                String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                String name = invoke.get().getMethodSignature().getName();
                setsAuthorization |= !headerValues(stmt).isEmpty();
                readsCaller |= SECURITY_CONTEXT.contains(owner) || name.equals("getTokenValue")
                        || authorization(invoke.get()) && HEADER_GETTERS.contains(name);
                // authorize(..) is the managers' only method.
                authorizedClient |= AUTHORIZED_CLIENT_MANAGERS.contains(owner);
            }
        }
        return new Reads(setsAuthorization, readsCaller, authorizedClient);
    }

    private static boolean authorization(AbstractInvokeExpr invoke) {
        return invoke.getArgCount() > 0 && invoke.getArg(0) instanceof StringConstant header
                && header.getValue().equalsIgnoreCase("Authorization");
    }

    /**
     * The values a statement puts in the {@code Authorization} header: {@code setBearerAuth(token)},
     * {@code setBasicAuth(..)}, {@code basicAuthentication(..)}, or {@code set}/{@code add}/{@code header}/
     * {@code defaultHeader}/{@code put("Authorization", ..)}.
     */
    private static List<Value> headerValues(Stmt stmt) {
        Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
        if (invoke.isEmpty()) {
            return List.of();
        }
        String name = invoke.get().getMethodSignature().getName();
        if (SETS_AUTHORIZATION.contains(name) && invoke.get().getArgCount() > 0) {
            return List.copyOf(invoke.get().getArgs());
        }
        return authorization(invoke.get()) && HEADER_SETTERS.contains(name) && invoke.get().getArgCount() > 1
                ? List.copyOf(invoke.get().getArgs().subList(1, invoke.get().getArgCount())) : List.of();
    }

    // Decision 0083 amended: the header's value, followed back.

    /**
     * Where a header's value comes from, from the weakest to the strongest: a fixed value (a constant, the
     * configuration), one AuthTracer can't follow, an authorized client's token, the caller's.
     */
    private enum Source {
        FIXED, UNKNOWN, CLIENT, CALLER
    }

    /**
     * @param where where it is read, or for {@code UNKNOWN} where AuthTracer stopped
     * @param registration for an authorized client's token, the registration its request names, when it names one
     */
    private record Traced(Source source, String where, String registration) {

        static final Traced FIXED = new Traced(Source.FIXED, null);

        Traced(Source source, String where) {
            this(source, where, null);
        }

        /**
         * The stronger of the two: of several values (concatenated, or alternatives) the strongest decides.
         */
        Traced or(Traced other) {
            return other.source().compareTo(source) > 0 ? other : this;
        }
    }

    /**
     * A value followed back: through locals and casts; the configuration ({@code @Value},
     * {@code @ConfigurationProperties}); an application field to each value the application assigns it; a parameter
     * to each argument the application's calls (and a lambda's captured values) pass; an application method,
     * through each implementation, to what it returns; a library call to what it is made from (its receiver and
     * arguments, concatenation too). The security context, the incoming request's {@code Authorization} header and a
     * token's {@code getTokenValue()} are the caller's; an authorized-client manager's token is its own.
     *
     * @param seen what each local already followed was followed to
     */
    private Traced trace(JavaSootMethod method, Value value, int depth, Map<String, Traced> seen) {
        if (value instanceof sootup.core.jimple.common.constant.Constant) {
            return Traced.FIXED;
        }
        if (value instanceof JCastExpr cast) {
            return trace(method, cast.getOp(), depth, seen);
        }
        if (depth <= 0) {
            return new Traced(Source.UNKNOWN, "a value too many steps away, in " + name(method));
        }
        if (value instanceof Local local) {
            String key = method.getSignature() + " " + local.getName();
            Traced known = seen.get(key);
            if (known != null) {
                // Followed already, or being followed (a loop adds nothing).
                return known;
            }
            seen.put(key, Traced.FIXED);
            if (configured().of(method, local).known()) {
                return Traced.FIXED;
            }
            Traced traced = Traced.FIXED;
            for (Value definition : Locals.definitions(method.getBody(), local)) {
                traced = traced.or(definition instanceof sootup.core.jimple.common.expr.JNewArrayExpr
                        ? Locals.elements(method.getBody(), local).stream().map(element -> trace(method, element,
                                depth - 1, seen)).reduce(Traced.FIXED, Traced::or)
                        : trace(method, definition, depth - 1, seen));
            }
            seen.put(key, traced);
            return traced;
        }
        if (value instanceof JParameterRef parameter) {
            return parameter(method, parameter.getIndex(), depth, seen);
        }
        if (value instanceof JFieldRef field) {
            return field(field, depth, seen);
        }
        if (value instanceof JDynamicInvokeExpr dynamic) {
            // A lambda's result, or a concatenation of its arguments.
            Traced traced = lambda(dynamic).map(target -> returned(target, depth, seen)).orElse(Traced.FIXED);
            for (Value argument : dynamic.getArgs()) {
                traced = traced.or(trace(method, argument, depth - 1, seen));
            }
            return traced;
        }
        if (value instanceof AbstractInvokeExpr call) {
            return invoked(method, call, depth, seen);
        }
        if (value instanceof JNewExpr created) {
            // A string built here is what is appended to it; another object's content is set where AuthTracer
            // doesn't follow.
            return created.getType().getFullyQualifiedName().startsWith("java.lang.String") ? Traced.FIXED
                    : new Traced(Source.UNKNOWN, "a new " + simpleName(created.getType().getFullyQualifiedName())
                            + " in " + name(method));
        }
        return new Traced(Source.UNKNOWN, "an expression in " + name(method));
    }

    private Traced invoked(JavaSootMethod method, AbstractInvokeExpr call, int depth, Map<String, Traced> seen) {
        String owner = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = call.getMethodSignature().getName();
        if (AUTHORIZED_CLIENT_MANAGERS.contains(owner)) {
            // The registration the request names: one for the signed-in user gives their token.
            Optional<String> registration = authorizedRegistration(method);
            String grant = registration.map(this::grant).orElse("");
            if (grant.equals(PASSWORD)) {
                return new Traced(Source.UNKNOWN, name(method) + " (a password grant, which Spring Security 7.1.1 has"
                        + " no provider for, of registration " + registration.get() + ")");
            }
            return USER_GRANTS.contains(grant) ? new Traced(Source.CALLER, name(method) + " (the signed-in user's "
                    + grant + " token of registration " + registration.get() + ")")
                    : new Traced(Source.CLIENT, name(method), registration.orElse(null));
        }
        if (SECURITY_CONTEXT.contains(owner) || authorization(call) && HEADER_GETTERS.contains(name)) {
            return new Traced(Source.CALLER, name(method));
        }
        if (context.isApplication(call.getMethodSignature().getDeclClassType())) {
            List<JavaSootMethod> targets = calls().targets(call).stream().filter(JavaSootMethod::hasBody).toList();
            if (targets.isEmpty()) {
                return new Traced(Source.UNKNOWN, simpleName(owner) + "#" + name);
            }
            return targets.stream().map(target -> returned(target, depth, seen)).reduce(Traced.FIXED, Traced::or);
        }
        // A library call: what it is made from.
        Traced traced = call instanceof AbstractInstanceInvokeExpr instance
                ? trace(method, instance.getBase(), depth - 1, seen) : Traced.FIXED;
        for (Value argument : call.getArgs()) {
            traced = traced.or(trace(method, argument, depth - 1, seen));
        }
        // A token's value whose token AuthTracer doesn't see made: the caller's, as the code around it reads.
        return name.equals("getTokenValue") && traced.source().compareTo(Source.CLIENT) < 0
                ? new Traced(Source.CALLER, name(method)) : traced;
    }

    /**
     * What a method returns.
     */
    private Traced returned(JavaSootMethod method, int depth, Map<String, Traced> seen) {
        Traced traced = Traced.FIXED;
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JReturnStmt returned) {
                traced = traced.or(trace(method, returned.getOp(), depth - 1, seen));
            }
        }
        return traced;
    }

    /**
     * A parameter: what a lambda captured, else what the application's calls of the method pass.
     */
    private Traced parameter(JavaSootMethod method, int index, int depth, Map<String, Traced> seen) {
        Traced traced = null;
        // A lambda body that uses this is an instance method: the first value its invokedynamic captures is this.
        int receiver = method.isStatic() ? 0 : 1;
        for (Map.Entry<JavaSootMethod, AbstractInvokeExpr> site : uses().calls().getOrDefault(
                method.getSignature().getSubSignature().toString(), List.of())) {
            ClassType declared = site.getValue().getMethodSignature().getDeclClassType();
            ClassType owner = method.getDeclaringClassType();
            Traced passed = null;
            if (site.getValue() instanceof JDynamicInvokeExpr dynamic) {
                if (lambda(dynamic).filter(target -> target.getSignature().equals(method.getSignature())).isEmpty()) {
                    continue;
                }
                passed = index + receiver < dynamic.getArgCount()
                        ? trace(site.getKey(), dynamic.getArg(index + receiver), depth - 1, seen)
                        : input(site.getKey(), method, depth, seen).orElse(null);
            }
            else if (declared.equals(owner) || context.superClassesOf(owner).contains(declared)
                    || context.interfacesOf(owner).contains(declared)
                    || context.superClassesOf(declared).contains(owner)) {
                passed = trace(site.getKey(), site.getValue().getArg(index), depth - 1, seen);
            }
            if (passed != null) {
                traced = traced == null ? passed : traced.or(passed);
            }
        }
        return traced != null ? traced : new Traced(Source.UNKNOWN, "parameter " + index + " of " + name(method));
    }

    /**
     * A lambda's input, when the lambda is handed to a library call on a receiver ({@code mono.map(context -> ..)},
     * {@code .flatMap(token -> ..)}, {@code list.forEach(..)}): what the receiver holds, so a token is followed along a
     * Reactor pipeline to where it starts. Empty when the lambda goes elsewhere.
     */
    private Optional<Traced> input(JavaSootMethod site, JavaSootMethod body, int depth, Map<String, Traced> seen) {
        Set<Local> lambdas = new HashSet<>();
        for (Stmt stmt : site.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition
                    && definition.getRightOp() instanceof JDynamicInvokeExpr dynamic
                    && lambda(dynamic).filter(target -> target.getSignature().equals(body.getSignature())).isPresent()
                    && definition.getLeftOp() instanceof Local local) {
                lambdas.add(local);
            }
        }
        Traced traced = null;
        for (Stmt stmt : site.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt).filter(call -> call
                    instanceof AbstractInstanceInvokeExpr && !context.isApplication(call.getMethodSignature()
                            .getDeclClassType()) && call.getArgs().stream().anyMatch(lambdas::contains));
            if (invoke.isPresent()) {
                Traced held = trace(site, ((AbstractInstanceInvokeExpr) invoke.get()).getBase(), depth - 1, seen);
                traced = traced == null ? held : traced.or(held);
            }
        }
        return Optional.ofNullable(traced);
    }

    /**
     * The client registration an authorize request the method builds names, when it names one constant:
     * {@code OAuth2AuthorizeRequest.withClientRegistrationId("x")}.
     */
    private static Optional<String> authorizedRegistration(JavaSootMethod method) {
        Set<String> registrations = new HashSet<>();
        for (Stmt stmt : method.getBody().getStmts()) {
            Locals.invoke(stmt).filter(invoke -> invoke.getMethodSignature().getName()
                    .equals("withClientRegistrationId") && invoke.getArgCount() == 1
                    && invoke.getArg(0) instanceof StringConstant)
                    .ifPresent(invoke -> registrations.add(((StringConstant) invoke.getArg(0)).getValue()));
        }
        return registrations.size() == 1 ? registrations.stream().findFirst() : Optional.empty();
    }

    /**
     * An application field: each value the application assigns it. A library's is fixed.
     */
    private Traced field(JFieldRef field, int depth, Map<String, Traced> seen) {
        if (!context.isApplication(field.getFieldSignature().getDeclClassType())) {
            return Traced.FIXED;
        }
        List<Map.Entry<JavaSootMethod, Value>> writes = uses().writes().getOrDefault(field.getFieldSignature()
                .toString(), List.of());
        if (writes.isEmpty()) {
            return new Traced(Source.UNKNOWN, "the field " + simpleName(field.getFieldSignature().getDeclClassType()
                    .getFullyQualifiedName()) + "." + field.getFieldSignature().getName());
        }
        return writes.stream().map(write -> trace(write.getKey(), write.getValue(), depth - 1, seen))
                .reduce(Traced.FIXED, Traced::or);
    }

    /**
     * The method as a person finds it: a lambda by the method it is written in (decision 0089).
     */
    private String name(JavaSootMethod method) {
        if (enclosing == null) {
            enclosing = new EnclosingMethods(context);
        }
        JavaSootMethod written = enclosing.of(method);
        return simpleName(written.getDeclaringClassType().getFullyQualifiedName()) + "#" + written.getName();
    }

    /**
     * The application's calls by the sub-signature they call (a lambda's site by its target's), and its field
     * assignments by field.
     */
    private record Uses(Map<String, List<Map.Entry<JavaSootMethod, AbstractInvokeExpr>>> calls,
            Map<String, List<Map.Entry<JavaSootMethod, Value>>> writes) {
    }

    private Uses uses() {
        if (uses == null) {
            Map<String, List<Map.Entry<JavaSootMethod, AbstractInvokeExpr>>> calls = new java.util.HashMap<>();
            Map<String, List<Map.Entry<JavaSootMethod, Value>>> writes = new java.util.HashMap<>();
            for (JavaSootClass cls : context.applicationClasses()) {
                for (JavaSootMethod method : cls.getMethods()) {
                    for (Stmt stmt : method.hasBody() ? method.getBody().getStmts() : List.<Stmt>of()) {
                        Locals.invoke(stmt).ifPresent(invoke -> calls.computeIfAbsent(invoke.getMethodSignature()
                                .getSubSignature().toString(), key -> new ArrayList<>()).add(Map.entry(method, invoke)));
                        if (stmt instanceof AbstractDefinitionStmt definition
                                && definition.getRightOp() instanceof JDynamicInvokeExpr dynamic) {
                            lambda(dynamic).ifPresent(target -> calls.computeIfAbsent(target.getSignature()
                                    .getSubSignature().toString(), key -> new ArrayList<>())
                                    .add(Map.entry(method, dynamic)));
                        }
                        if (stmt instanceof JAssignStmt assign && assign.getLeftOp() instanceof JFieldRef field) {
                            writes.computeIfAbsent(field.getFieldSignature().toString(), key -> new ArrayList<>())
                                    .add(Map.entry(method, assign.getRightOp()));
                        }
                    }
                }
            }
            uses = new Uses(calls, writes);
        }
        return uses;
    }

    private CallTraversal calls() {
        if (calls == null) {
            calls = new CallTraversal(context);
        }
        return calls;
    }

    private ConfiguredValues configured() {
        if (configured == null) {
            configured = new ConfiguredValues(context);
        }
        return configured;
    }

    private static String simpleName(String className) {
        return MethodNames.simpleName(className).replace('$', '.');
    }
}
