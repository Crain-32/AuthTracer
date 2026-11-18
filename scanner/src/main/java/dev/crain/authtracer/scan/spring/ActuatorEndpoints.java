package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.Payloads;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0041: Spring Boot Actuator's web endpoints. Every {@code @Endpoint} (or {@code @WebEndpoint}) class, Spring
 * Boot's own and the application's, serves its operations under {@code management.endpoints.web.base-path}
 * ({@code /actuator}) when exposed ({@code management.endpoints.web.exposure.include}, by default only {@code health})
 * and accessible ({@code management.endpoint.<id>.access}, {@code management.endpoints.access.default}): a
 * {@code @ReadOperation} is {@code GET}, a {@code @WriteOperation} {@code POST}, a {@code @DeleteOperation}
 * {@code DELETE}, and each {@code @Selector} parameter a path segment. Spring Boot's endpoints answer with Boot's own
 * types, so only the application's endpoints get a response; the Ingress is what matters.
 */
@Supports({Feature.LIBRARY_ENDPOINTS, Feature.REQUEST_RULES})
final class ActuatorEndpoints {

    private static final String WEB_ENDPOINTS =
            "org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointAutoConfiguration";
    private static final String ENDPOINT = "org.springframework.boot.actuate.endpoint.annotation.Endpoint";
    private static final String WEB_ENDPOINT = "org.springframework.boot.actuate.endpoint.web.annotation.WebEndpoint";
    private static final String SELECTOR = "org.springframework.boot.actuate.endpoint.annotation.Selector";
    private static final Map<String, String> OPERATIONS = Map.of(
            "org.springframework.boot.actuate.endpoint.annotation.ReadOperation", "GET",
            "org.springframework.boot.actuate.endpoint.annotation.WriteOperation", "POST",
            "org.springframework.boot.actuate.endpoint.annotation.DeleteOperation", "DELETE");
    /**
     * Spring Boot 4.1.1's endpoints, as {@code @Endpoint} classes (found in its jars).
     */
    private static final List<String> BUILT_IN = List.of(
            "org.springframework.boot.health.actuate.endpoint.HealthEndpoint",
            "org.springframework.boot.actuate.info.InfoEndpoint",
            "org.springframework.boot.actuate.env.EnvironmentEndpoint",
            "org.springframework.boot.actuate.beans.BeansEndpoint",
            "org.springframework.boot.actuate.autoconfigure.condition.ConditionsReportEndpoint",
            "org.springframework.boot.actuate.context.properties.ConfigurationPropertiesReportEndpoint",
            "org.springframework.boot.actuate.logging.LoggersEndpoint",
            "org.springframework.boot.actuate.management.HeapDumpWebEndpoint",
            "org.springframework.boot.actuate.management.ThreadDumpEndpoint",
            "org.springframework.boot.actuate.web.mappings.MappingsEndpoint",
            "org.springframework.boot.actuate.scheduling.ScheduledTasksEndpoint",
            "org.springframework.boot.actuate.sbom.SbomEndpoint",
            "org.springframework.boot.cache.actuate.endpoint.CachesEndpoint",
            "org.springframework.boot.micrometer.metrics.actuate.endpoint.MetricsEndpoint",
            "org.springframework.boot.micrometer.metrics.autoconfigure.export.prometheus.PrometheusScrapeEndpoint",
            "org.springframework.boot.actuate.context.ShutdownEndpoint",
            "org.springframework.boot.actuate.audit.AuditEventsEndpoint",
            "org.springframework.boot.actuate.web.exchanges.HttpExchangesEndpoint",
            "org.springframework.boot.actuate.startup.StartupEndpoint",
            "org.springframework.boot.actuate.logging.LogFileWebEndpoint",
            // Spring Cloud 2025.1's: refresh and restart (spring-cloud-context), the Gateway's routes, Stream's
            // bindings and channels, Function's functions, Commons' features.
            "org.springframework.cloud.endpoint.RefreshEndpoint",
            "org.springframework.cloud.context.restart.RestartEndpoint",
            "org.springframework.cloud.gateway.actuate.GatewayControllerEndpoint",
            "org.springframework.cloud.stream.endpoint.BindingsEndpoint",
            "org.springframework.cloud.stream.endpoint.ChannelsEndpoint",
            "org.springframework.cloud.function.actuator.FunctionsEndpoint",
            "org.springframework.cloud.client.actuator.FeaturesEndpoint");
    private static final String REST_CONTROLLER_ENDPOINT =
            "org.springframework.boot.actuate.endpoint.web.annotation.RestControllerEndpoint";
    /**
     * Spring Cloud's writable environment ({@code management.endpoint.env.post.enabled}): its web extension writes
     * ({@code POST}) and resets ({@code DELETE}) properties, the start of the classic env-then-refresh attack.
     */
    private static final String WRITABLE_ENVIRONMENT =
            "org.springframework.cloud.context.environment.WritableEnvironmentEndpointWebExtension";
    /**
     * Endpoints that need a bean besides their class.
     */
    private static final Map<String, String> NEEDS = Map.of(
            "auditevents", "org.springframework.boot.actuate.audit.AuditEventRepository",
            "httpexchanges", "org.springframework.boot.actuate.web.exchanges.HttpExchangeRepository");
    private static final String BUFFERING_STARTUP =
            "org.springframework.boot.context.metrics.buffering.BufferingApplicationStartup";

    /**
     * An endpoint: its id, path and class.
     */
    record Endpoint(String id, String path, JavaSootClass type) {
    }

    /**
     * Access levels, least first: a level is capped at the most the application permits.
     */
    private static final List<String> ACCESS_LEVELS = List.of("NONE", "READ_ONLY", "UNRESTRICTED");

    private final ScanContext context;
    /**
     * Which endpoint each operation {@link #detect()} found belongs to.
     */
    private final Map<MethodSignature, String> endpointIds = new HashMap<>();
    /**
     * The endpoint classes AuthTracer knows of and the application's, found once.
     */
    private List<JavaSootClass> endpointClasses;

    ActuatorEndpoints(ScanContext context) {
        this.context = context;
    }

    /**
     * The id of the endpoint whose operation the handler is, among those {@link #detect()} found.
     */
    Optional<String> endpointId(JavaSootMethod handler) {
        return Optional.ofNullable(endpointIds.get(handler.getSignature()));
    }

    /**
     * Actuator's web endpoints are on: a negative {@code management.server.port} turns them off (Boot 4.1.1's
     * {@code ManagementPortType.DISABLED}).
     */
    boolean active() {
        return context.findClass(WEB_ENDPOINTS).isPresent()
                && context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)
                && !managementPort().filter(port -> port.startsWith("-")).isPresent();
    }

    /**
     * The endpoints' base path; on a port of their own, under {@code management.server.base-path}.
     */
    String basePath() {
        String base = context.properties().get("management.endpoints.web.base-path").orElse("/actuator");
        String endpoints = base.isEmpty() || base.equals("/") ? "" : RequestMappings.join("", base);
        String server = ownPort() ? context.properties().get("management.server.base-path").orElse("") : "";
        return server.isEmpty() || server.equals("/") ? endpoints : RequestMappings.join(server, endpoints);
    }

    private boolean ownPort() {
        return managementPort().filter(port -> !port.equals(context.properties().get("server.port")
                .map(String::trim).orElse("8080"))).isPresent();
    }

    private Optional<String> managementPort() {
        return context.properties().get("management.server.port").map(String::trim).filter(port -> port
                .matches("-?\\d+"));
    }

    /**
     * The endpoints served over HTTP, by id.
     */
    Map<String, Endpoint> exposed() {
        Map<String, Endpoint> endpoints = new LinkedHashMap<>();
        if (!active()) {
            return endpoints;
        }
        for (JavaSootClass cls : endpointClasses()) {
            Optional<String> id = id(cls);
            if (id.isPresent() && exposed(id.get()) && !access(id.get()).equals("NONE") && available(id.get())) {
                endpoints.put(id.get(), new Endpoint(id.get(), path(id.get()), cls));
            }
        }
        return endpoints;
    }

    /**
     * Every endpoint's id, exposed or not, for {@code EndpointRequest.to(SomeEndpoint.class)}.
     */
    Optional<String> id(String className) {
        return context.findClass(className).flatMap(this::id);
    }

    private Optional<String> id(JavaSootClass cls) {
        return annotation(cls).flatMap(found -> Annotations.string(found, "id"));
    }

    /**
     * {@code @WebEndpoint} and {@code @RestControllerEndpoint} first: each is meta-annotated with an {@code @Endpoint}
     * that has no id of its own.
     */
    private Optional<AnnotationUsage> annotation(JavaSootClass cls) {
        return context.findAnnotation(cls, WEB_ENDPOINT).or(() -> context.findAnnotation(cls, REST_CONTROLLER_ENDPOINT))
                .or(() -> context.findAnnotation(cls, ENDPOINT));
    }

    /**
     * {@code management.endpoints.web.path-mapping.<id>}, under the base path. Boot 4.1.1's
     * {@code MappingWebEndpointPathMapper} keys the mapping by {@link #canonicalId}: {@code path-mapping.heapDump}
     * maps {@code heapdump}.
     */
    String path(String id) {
        String mapping = "management.endpoints.web.path-mapping.";
        return RequestMappings.join(basePath(), context.properties().get(mapping + id)
                .or(() -> context.properties().namesUnder(mapping).stream()
                        .filter(name -> canonicalId(name).equals(canonicalId(id))).findFirst()
                        .flatMap(name -> context.properties().get(mapping + name)))
                .orElse(id));
    }

    /**
     * Included (by default only {@code health}; a comma-separated list or a YAML one) and not excluded, each entry
     * compared as Boot 4.1.1's {@code IncludeExcludeEndpointFilter} compares it: as an {@link #canonicalId}.
     */
    private boolean exposed(String id) {
        List<String> included = context.properties().list("management.endpoints.web.exposure.include");
        List<String> include = included.isEmpty() ? List.of("health") : included;
        List<String> exclude = context.properties().list("management.endpoints.web.exposure.exclude");
        return (include.contains("*") || named(include, id)) && !exclude.contains("*") && !named(exclude, id);
    }

    private static boolean named(List<String> names, String id) {
        return names.stream().anyMatch(name -> canonicalId(name).equals(canonicalId(id)));
    }

    /**
     * An endpoint id as Boot 4.1.1's {@code EndpointId} compares two: lower case, its letters and digits only
     * ({@code Health}, {@code HTTP-Exchanges} and {@code http_exchanges} are {@code health} and
     * {@code httpexchanges}).
     */
    static String canonicalId(String value) {
        return value.toLowerCase(Locale.ENGLISH).replaceAll("[^a-z0-9]", "");
    }

    /**
     * The paths besides its own that serve the health endpoint, for {@code server} (the application's server:
     * Boot 4.1.1's {@code WebMvcHealthEndpointExtensionAutoConfiguration} and its WebFlux twin) or
     * {@code management} (a management server on a port of its own, under its base path): each health group's
     * {@code management.endpoint.health.group.<name>.additional-path} ({@code server:/healthz}), and, with
     * {@code management.endpoint.health.probes.add-additional-paths=true}, the liveness and readiness probes'
     * {@code /livez} and {@code /readyz} on the server, unless a group of that name has a path of its own.
     */
    List<String> additionalHealthPaths(String namespace) {
        if (!exposed().containsKey("health")) {
            return List.of();
        }
        String groups = "management.endpoint.health.group.";
        List<String> paths = new ArrayList<>();
        Set<String> ownPaths = new HashSet<>();
        for (String name : context.properties().namesUnder(groups)) {
            int dot = name.indexOf('.');
            if (dot < 0 || !canonicalId(name.substring(dot + 1)).equals("additionalpath")) {
                continue;
            }
            Optional<String> value = context.properties().get(groups + name).map(String::trim);
            int colon = value.map(found -> found.indexOf(':')).orElse(-1);
            if (colon <= 0) {
                continue;
            }
            ownPaths.add(name.substring(0, dot));
            String path = RequestMappings.join("", value.get().substring(colon + 1).trim());
            String space = value.get().substring(0, colon).trim().toLowerCase(Locale.ENGLISH);
            if (space.equals(namespace) && namespace.equals("server")) {
                paths.add(path);
            }
            else if (space.equals(namespace) && namespace.equals("management") && ownPort()) {
                paths.add(RequestMappings.join(context.properties().get("management.server.base-path").orElse(""),
                        path));
            }
        }
        boolean probes = context.properties().flag("management.endpoint.health.probes.enabled").orElse(true)
                && context.properties().get("management.endpoint.health.probes.add-additional-paths")
                        .filter("true"::equalsIgnoreCase).isPresent();
        if (probes && namespace.equals("server")) {
            Map.of("liveness", "/livez", "readiness", "/readyz").forEach((probe, path) -> {
                if (!ownPaths.contains(probe)) {
                    paths.add(path);
                }
            });
        }
        return paths.stream().distinct().sorted().toList();
    }

    /**
     * {@code NONE}, {@code READ_ONLY} or {@code UNRESTRICTED}, as Boot 4.1.1's {@code PropertiesEndpointAccessResolver}
     * resolves it: the endpoint's own {@code access}, else its legacy {@code enabled}; else every endpoint's
     * {@code management.endpoints.access.default}, else the legacy {@code enabled-by-default}; else the endpoint's
     * own default ({@code shutdown}'s and {@code heapdump}'s is none). Then capped by
     * {@code management.endpoints.access.max-permitted}.
     */
    String access(String id) {
        String access = access("management.endpoint." + id + ".access", "management.endpoint." + id + ".enabled")
                .or(() -> access("management.endpoints.access.default", "management.endpoints.enabled-by-default"))
                .orElse(defaultAccess(id));
        String permitted = context.properties().get("management.endpoints.access.max-permitted")
                .map(ActuatorEndpoints::accessLevel).orElse("UNRESTRICTED");
        return ACCESS_LEVELS.indexOf(access) > ACCESS_LEVELS.indexOf(permitted) ? permitted : access;
    }

    private Optional<String> access(String accessProperty, String enabledProperty) {
        return context.properties().get(accessProperty).map(ActuatorEndpoints::accessLevel)
                .or(() -> context.properties().flag(enabledProperty).map(enabled -> enabled ? "UNRESTRICTED" : "NONE"));
    }

    private static String accessLevel(String property) {
        return property.trim().toUpperCase(Locale.ROOT).replace('-', '_');
    }

    /**
     * The endpoint's own default access: its {@code @Endpoint(defaultAccess = ..)} ({@code shutdown}'s is none; Boot
     * 4.1.1's endpoint annotations have no {@code enableByDefault} left to read), else unrestricted.
     */
    private String defaultAccess(String id) {
        return endpointClasses().stream().filter(cls -> id(cls).filter(id::equals).isPresent()).findFirst()
                .flatMap(this::annotation).flatMap(found -> Annotations.string(found, "defaultAccess"))
                .filter(ACCESS_LEVELS::contains).orElse("UNRESTRICTED");
    }

    private List<JavaSootClass> endpointClasses() {
        if (endpointClasses == null) {
            List<JavaSootClass> classes = new ArrayList<>();
            BUILT_IN.forEach(name -> context.findClass(name).ifPresent(classes::add));
            context.applicationClasses().stream().filter(cls -> annotation(cls).isPresent()).forEach(classes::add);
            endpointClasses = classes;
        }
        return endpointClasses;
    }

    private boolean available(String id) {
        if (id.equals("gateway")) {
            // The Gateway's endpoint comes with the reactive Gateway's auto-configuration.
            return WebStack.reactive(context);
        }
        if (id.equals("logfile")) {
            return context.properties().get("logging.file.name").isPresent()
                    || context.properties().get("logging.file.path").isPresent();
        }
        if (id.equals("startup")) {
            return bufferingStartup();
        }
        String bean = NEEDS.get(id);
        // The beans needed are interfaces: the bean's type is one, or implements it.
        return bean == null || SpringBeans.beanMethods(context).stream()
                .anyMatch(method -> method.getReturnType() instanceof ClassType returned
                        && (returned.getFullyQualifiedName().equals(bean) || context.interfacesOf(returned).stream()
                                .anyMatch(type -> type.getFullyQualifiedName().equals(bean))));
    }

    /**
     * Boot 4.1.1's {@code ApplicationStartupCondition}: the application's startup is a
     * {@code BufferingApplicationStartup}, set with {@code app.setApplicationStartup(new
     * BufferingApplicationStartup(n))} (or the builder's {@code applicationStartup(..)}) in {@code main}.
     */
    private boolean bufferingStartup() {
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isPresent() && Set.of("setApplicationStartup", "applicationStartup")
                            .contains(invoke.get().getMethodSignature().getName()) && invoke.get().getArgCount() == 1
                            && invoke.get().getArg(0) instanceof Local startup && Locals.created(method.getBody(),
                                    startup).filter(type -> type.getFullyQualifiedName().equals(BUFFERING_STARTUP))
                                    .isPresent()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Each exposed endpoint's operations as Ingress; a read-only endpoint has only its reads.
     */
    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        for (Endpoint endpoint : exposed().values()) {
            boolean readOnly = access(endpoint.id()).equals("READ_ONLY");
            boolean application = context.isApplication(endpoint.type().getType());
            if (context.hasAnnotation(endpoint.type(), REST_CONTROLLER_ENDPOINT)) {
                mappings.addAll(controllerOperations(endpoint, readOnly));
                continue;
            }
            List<JavaSootMethod> methods = new ArrayList<>(endpoint.type().getMethods());
            if (endpoint.id().equals("env") && context.properties().flag("management.endpoint.env.post.enabled")
                    .orElse(false)) {
                context.findClass(WRITABLE_ENVIRONMENT).ifPresent(extension -> methods.addAll(extension.getMethods()));
            }
            for (JavaSootMethod method : methods) {
                Optional<String> httpMethod = OPERATIONS.entrySet().stream()
                        .filter(operation -> context.hasAnnotation(method, operation.getKey()))
                        .map(Map.Entry::getValue).findFirst();
                if (httpMethod.isEmpty() || readOnly && !httpMethod.get().equals("GET")) {
                    continue;
                }
                StringBuilder route = new StringBuilder(endpoint.path());
                for (int i = 0; i < method.getParameterCount(); i++) {
                    if (!context.classFiles().parameterAnnotations(method.getSignature(), i).contains(SELECTOR)) {
                        continue;
                    }
                    String name = method.hasBody() ? method.getBody().getParameterLocal(i).getName() : "arg" + i;
                    boolean remaining = context.classFiles().parameterAnnotationElement(method.getSignature(), i,
                            SELECTOR, "match").filter("ALL_REMAINING"::equals).isPresent();
                    route.append(remaining ? "/{*" + name + "}" : "/{" + name + "}");
                }
                Ingress ingress = Ingress.of(httpMethod.get(), route.toString(),
                        MethodNames.codeRef(method.getSignature()));
                mappings.add(new RequestMappings.Mapping(application ? ingress.withResponse(Payloads.returnedBy(
                        context, method.getSignature()).orElse(null)) : ingress, method, true));
                endpointIds.put(method.getSignature(), endpoint.id());
                if (endpoint.id().equals("health") && httpMethod.get().equals("GET")
                        && route.toString().equals(endpoint.path())) {
                    // A health group's own path runs the health endpoint's read, for the group.
                    for (String namespace : List.of("server", "management")) {
                        additionalHealthPaths(namespace).forEach(path -> mappings.add(new RequestMappings.Mapping(
                                Ingress.of("GET", path, MethodNames.codeRef(method.getSignature())), method, true)));
                    }
                }
            }
        }
        return mappings;
    }

    /**
     * A {@code @RestControllerEndpoint}'s operations are Spring MVC mappings (in its class and superclasses) under its
     * path: the Gateway's {@code GET /actuator/gateway/routes}, {@code POST /actuator/gateway/routes/{id}}, ...
     */
    private List<RequestMappings.Mapping> controllerOperations(Endpoint endpoint, boolean readOnly) {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        RequestMappings reader = new RequestMappings(context);
        List<JavaSootClass> chain = new ArrayList<>(List.of(endpoint.type()));
        context.superClassesOf(endpoint.type().getType()).forEach(type -> context.findClass(type)
                .ifPresent(chain::add));
        Set<String> seen = new HashSet<>();
        for (JavaSootClass cls : chain) {
            for (JavaSootMethod method : cls.getMethods()) {
                Optional<RequestMappings.MappingInfo> info = reader.mappingInfo(method);
                if (info.isEmpty()) {
                    continue;
                }
                for (String path : info.get().paths()) {
                    for (String httpMethod : info.get().methods()) {
                        String verb = httpMethod.equals("*") ? "GET" : httpMethod;
                        if (readOnly && !verb.equals("GET") || !seen.add(verb + " " + path)) {
                            continue;
                        }
                        mappings.add(new RequestMappings.Mapping(Ingress.of(verb, RequestMappings.join(endpoint.path(),
                                path), MethodNames.codeRef(method.getSignature())), method, true));
                        endpointIds.put(method.getSignature(), endpoint.id());
                    }
                }
            }
        }
        return mappings;
    }
}
