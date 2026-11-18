package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Ingress;
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
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.ref.JStaticFieldRef;
import sootup.core.jimple.common.stmt.AbstractDefinitionStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0043: Spring Cloud Gateway (5.0, WebFlux server and Server MVC) routes. Each route is an Ingress for its {@code Path}
 * predicate's patterns (and {@code Method}s) that forwards to its {@code uri}: an Egress with the path the filters
 * leave ({@code StripPrefix}, {@code PrefixPath}, {@code RewritePath}, {@code SetPath}), which the linker links to
 * every endpoint under it. Routes come from {@code spring.cloud.gateway.server.webflux.routes} (or the pre-4.3
 * {@code spring.cloud.gateway.routes}), with its {@code default-filters}, from Server MVC's {@code routes} and
 * {@code routes-map}, and from {@code RouteLocatorBuilder} beans. The gateway passes the request's
 * headers on, so the caller's bearer token goes along (a relay) unless a filter removes or replaces
 * {@code Authorization}; {@code TokenRelay} relays the logged-in user's OAuth2 token.
 */
@Supports(Feature.GATEWAY_ROUTES)
final class GatewayRoutes {

    private static final String ROUTE_LOCATOR = "org.springframework.cloud.gateway.route.RouteLocator";
    private static final String BUILDER = "org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder$Builder";
    private static final String SPECS = "org.springframework.cloud.gateway.route.builder.";
    private static final String HTTP_METHOD = "org.springframework.http.HttpMethod";
    private static final String MVC_GATEWAY = "org.springframework.cloud.gateway.server.mvc.";
    private static final String MVC_ROUTER_FUNCTIONS = MVC_GATEWAY + "handler.GatewayRouterFunctions";
    private static final Set<String> MVC_METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
    private static final Set<String> MVC_FILTERS = Set.of("stripPrefix", "prefixPath", "setPath", "rewritePath",
            "removeRequestHeader", "setRequestHeader", "addRequestHeader", "tokenRelay");
    private static final String MVC_PROPERTIES =
            "org.springframework.cloud.gateway.server.mvc.config.GatewayMvcProperties";
    /**
     * The WebFlux server's routes (and their pre-4.3 key), then the Server MVC's, which have the same shape.
     */
    private static final List<String> PREFIXES = List.of("spring.cloud.gateway.server.webflux.routes",
            "spring.cloud.gateway.routes", "spring.cloud.gateway.server.webmvc.routes",
            "spring.cloud.gateway.mvc.routes");
    /**
     * The WebFlux server's (5.0.0 {@code GatewayProperties#defaultFilters}), by the routes' prefix: Server MVC has none.
     */
    private static final Map<String, String> DEFAULT_FILTERS = Map.of(
            "spring.cloud.gateway.server.webflux.routes", "spring.cloud.gateway.server.webflux.default-filters",
            "spring.cloud.gateway.routes", "spring.cloud.gateway.default-filters");
    /**
     * Server MVC's routes keyed by id (5.0.0 {@code GatewayMvcProperties#routesMap}), and the pre-4.3 key.
     */
    private static final List<String> ROUTE_MAPS = List.of("spring.cloud.gateway.server.webmvc.routes-map",
            "spring.cloud.gateway.mvc.routes-map");
    private static final Pattern SHORTCUT = Pattern.compile("\\s*([A-Za-z]+)\\s*=?\\s*(.*)", Pattern.DOTALL);
    private static final int MAX_ROUTES = 500;

    /**
     * A route, its filters as {@code Name=args} shortcuts.
     */
    record Route(String id, List<String> paths, List<String> methods, String uri, List<String> filters,
            CodeRef declaredAt) {
    }

    /**
     * A route's Ingress for one path and method, and the Egress it forwards to.
     */
    record Forward(Ingress ingress, Egress egress) {
    }

    /**
     * Where a lambda was created: the method, the {@code invokedynamic} whose arguments are what it captures, and
     * where that method was created, when it is a lambda too.
     */
    private record Captured(JavaSootMethod method, JDynamicInvokeExpr creation, Captured outer) {
    }

    private final ScanContext context;
    private final ConfiguredValues configured;

    GatewayRoutes(ScanContext context) {
        this.context = context;
        this.configured = new ConfiguredValues(context);
    }

    List<Forward> detect() {
        List<Forward> forwards = new ArrayList<>();
        if (context.findClass(ROUTE_LOCATOR).isEmpty() && context.findClass(MVC_PROPERTIES).isEmpty()) {
            return forwards;
        }
        List<Route> routes = new ArrayList<>(configured());
        routes.addAll(built());
        routes.addAll(mvcBuilt());
        for (Route route : routes) {
            for (String path : route.paths()) {
                for (String method : route.methods().isEmpty() ? List.of("*") : route.methods()) {
                    Ingress ingress = Ingress.of(method, path, route.declaredAt());
                    String uri = route.uri() == null ? "" : route.uri();
                    String baseUrl = uri.startsWith("lb://") ? "http://" + uri.substring("lb://".length()) : uri;
                    Egress egress = Egress.of("Gateway", method, downstream(path, route.filters()),
                            baseUrl.isEmpty() ? null : baseUrl, uri.isEmpty() ? null : "route " + route.id() + " uri "
                                    + uri, route.declaredAt().atLine(null), null);
                    String via = "gateway route " + route.id();
                    forwards.add(new Forward(ingress, egress.withCredentials(credentials(route.filters()), via)));
                }
            }
        }
        return forwards;
    }

    /**
     * What the gateway sends downstream: the request's own headers (so its bearer token) unless a filter removes or
     * sets {@code Authorization}. The filters change the request in their order, so the last word on the header
     * counts; {@code AddRequestHeader} adds a value after the caller's, which still goes along.
     */
    @Supports(Feature.CALL_CREDENTIALS)
    static Credentials credentials(List<String> filters) {
        Credentials sent = Credentials.RELAY;
        for (String filter : filters) {
            String name = name(filter);
            String args = args(filter).toLowerCase(Locale.ROOT);
            if (name.equals("TokenRelay")) {
                sent = Credentials.RELAY;
            }
            else if (name.equals("RemoveRequestHeader") && args.contains("authorization")) {
                sent = Credentials.NONE;
            }
            else if (name.equals("SetRequestHeader") && args.startsWith("authorization")) {
                sent = Credentials.STATIC;
            }
            else if (name.equals("AddRequestHeader") && args.startsWith("authorization") && sent == Credentials.NONE) {
                sent = Credentials.STATIC;
            }
        }
        return sent;
    }

    /**
     * The path the filters forward a request matching the pattern to; {@link Egress#UNKNOWN_TARGET} when a filter
     * changes it in a way AuthTracer can't read (a part count that isn't a number, a rewrite it can't apply), which the
     * linker reports rather than guess (decision 0082).
     */
    static String downstream(String pattern, List<String> filters) {
        String path = pattern;
        for (String filter : filters) {
            String args = args(filter);
            switch (name(filter)) {
                case "StripPrefix" -> {
                    // Spring Cloud Gateway's StripPrefix strips one part unless it is told how many.
                    OptionalInt read = args.isBlank() ? OptionalInt.of(1) : parse(args);
                    if (read.isEmpty()) {
                        return Egress.UNKNOWN_TARGET;
                    }
                    int parts = read.getAsInt();
                    List<String> segments = new ArrayList<>(List.of(path.split("/")));
                    segments.removeIf(String::isEmpty);
                    path = "/" + String.join("/", segments.subList(Math.min(parts, segments.size()),
                            segments.size()));
                }
                case "PrefixPath" -> path = args.trim() + path;
                case "SetPath" -> path = args.trim();
                case "RewritePath" -> {
                    int comma = args.indexOf(',');
                    if (comma > 0) {
                        String regex = args.substring(0, comma).trim();
                        String replacement = args.substring(comma + 1).trim().replace("$\\", "$");
                        try {
                            path = path.replaceAll(regex, replacement);
                        }
                        catch (RuntimeException invalid) {
                            return Egress.UNKNOWN_TARGET;
                        }
                    }
                }
                default -> {
                }
            }
        }
        return path.isEmpty() ? "/" : path;
    }

    private static OptionalInt parse(String text) {
        try {
            return OptionalInt.of(Integer.parseInt(text.trim()));
        }
        catch (NumberFormatException ex) {
            return OptionalInt.empty();
        }
    }

    private static String name(String shortcut) {
        Matcher matcher = SHORTCUT.matcher(shortcut);
        return matcher.matches() ? matcher.group(1) : shortcut;
    }

    private static String args(String shortcut) {
        Matcher matcher = SHORTCUT.matcher(shortcut);
        return matcher.matches() ? matcher.group(2) : "";
    }

    /**
     * Routes in the application's properties, shortcut ({@code Path=/api/**}) or expanded ({@code name}, {@code args}).
     */
    private List<Route> configured() {
        List<Route> routes = new ArrayList<>();
        for (String prefix : PREFIXES) {
            List<String> defaults = Optional.ofNullable(DEFAULT_FILTERS.get(prefix)).map(this::entries)
                    .orElse(List.of());
            for (int i = 0; i < MAX_ROUTES; i++) {
                String route = prefix + "[" + i + "]";
                if (!context.properties().hasPrefix(route + ".")) {
                    break;
                }
                routes.add(configured(route, route, defaults));
            }
        }
        // Server MVC's routes by id: routes-map.<id>.uri, .predicates, .filters.
        for (String map : ROUTE_MAPS) {
            context.properties().namesUnder(map + ".").stream().map(name -> name.split("[.\\[]", 2)[0])
                    .filter(id -> !id.isEmpty()).distinct()
                    .forEach(id -> routes.add(configured(map + "." + id, id, List.of())));
        }
        return routes;
    }

    /**
     * One route of the properties, at its key. The WebFlux server applies its default filters to every route of the
     * properties (5.0.0 {@code RouteDefinitionRouteLocator#getFilters}), not to those a {@code RouteLocator} bean
     * builds: each list's filters ordered by their place in it, a default first among equals.
     */
    private Route configured(String route, String fallbackId, List<String> defaults) {
        List<String> paths = new ArrayList<>();
        List<String> methods = new ArrayList<>();
        for (String predicate : entries(route + ".predicates")) {
            List<String> values = List.of(args(predicate).split(","));
            switch (name(predicate)) {
                case "Path" -> values.stream().map(String::trim).filter(value -> !value.isEmpty())
                        .forEach(paths::add);
                case "Method" -> values.stream().map(value -> value.trim().toUpperCase(Locale.ROOT))
                        .filter(value -> !value.isEmpty()).forEach(methods::add);
                default -> {
                }
            }
        }
        List<String> own = entries(route + ".filters");
        List<String> filters = new ArrayList<>();
        for (int i = 0; i < Math.max(defaults.size(), own.size()); i++) {
            if (i < defaults.size()) {
                filters.add(defaults.get(i));
            }
            if (i < own.size()) {
                filters.add(own.get(i));
            }
        }
        String id = context.properties().get(route + ".id").orElse(fallbackId);
        return new Route(id, paths, methods, context.properties().get(route + ".uri").orElse(null), filters,
                CodeRef.ofClass("application properties " + route));
    }

    /**
     * {@code predicates[0]=Path=/a/**} or {@code predicates[0].name=Path} with its {@code args.*}, as shortcuts.
     */
    private List<String> entries(String list) {
        List<String> entries = new ArrayList<>();
        for (int j = 0; j < MAX_ROUTES; j++) {
            String entry = list + "[" + j + "]";
            Optional<String> shortcut = context.properties().get(entry);
            Optional<String> name = context.properties().get(entry + ".name");
            if (shortcut.isPresent()) {
                entries.add(shortcut.get());
            }
            else if (name.isPresent()) {
                List<String> args = new ArrayList<>();
                for (int k = 0; k < MAX_ROUTES; k++) {
                    String genkey = entry + ".args._genkey_" + k;
                    Optional<String> arg = context.properties().get(entry + ".args[" + k + "]")
                            .or(() -> context.properties().get(genkey));
                    if (arg.isEmpty()) {
                        break;
                    }
                    args.add(arg.get());
                }
                for (String key : List.of("patterns", "pattern", "methods", "regexp", "replacement", "parts", "prefix",
                        "template", "name", "value")) {
                    context.properties().get(entry + ".args." + key).ifPresent(args::add);
                }
                entries.add(name.get() + "=" + String.join(",", args));
            }
            else {
                break;
            }
        }
        return entries;
    }

    /**
     * Routes a {@code RouteLocator} bean builds with {@code RouteLocatorBuilder}: each {@code route(..)} lambda and the
     * {@code filters(..)} lambdas inside it.
     */
    private List<Route> built() {
        List<Route> routes = new ArrayList<>();
        for (JavaSootMethod method : SpringBeans.beanMethods(context, ROUTE_LOCATOR)) {
            if (!method.hasBody()) {
                continue;
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                if (invoke.isEmpty() || !invoke.get().getMethodSignature().getDeclClassType()
                        .getFullyQualifiedName().equals(BUILDER)
                        || !invoke.get().getMethodSignature().getName().equals("route")) {
                    continue;
                }
                String id = invoke.get().getArgCount() == 2 && invoke.get().getArg(0) instanceof StringConstant name
                        ? name.getValue() : "route" + routes.size();
                Value lambda = invoke.get().getArg(invoke.get().getArgCount() - 1);
                Optional<JDynamicInvokeExpr> creation = lambda instanceof Local local
                        ? Locals.definition(method.getBody(), local).filter(JDynamicInvokeExpr.class::isInstance)
                                .map(JDynamicInvokeExpr.class::cast) : Optional.empty();
                Optional<JavaSootMethod> body = creation.flatMap(this::lambda);
                List<String> paths = new ArrayList<>();
                List<String> methods = new ArrayList<>();
                List<String> filters = new ArrayList<>();
                String[] uri = {null};
                body.ifPresent(found -> read(found, paths, methods, filters, uri, new HashSet<>(),
                        new Captured(method, creation.get(), null)));
                routes.add(new Route(id, paths, methods, uri[0], filters,
                        MethodNames.codeRef(method.getSignature(), stmt)));
            }
        }
        return routes;
    }

    /**
     * Server MVC's Java routes: a {@code RouterFunction} bean that starts each route with
     * {@code GatewayRouterFunctions.route(id)}, read in order: the builder's {@code GET(pattern, http())} (and the
     * other methods) or {@code route(path(..), ..)}, and the {@code before(uri(..))}, {@code before(stripPrefix(..))},
     * ... and {@code filter(lb(serviceId))} filter functions up to the next route. (Gateway Server MVC 5.0.0's
     * {@code HandlerFunctions.http()} takes no URI.)
     */
    private List<Route> mvcBuilt() {
        List<Route> routes = new ArrayList<>();
        for (JavaSootMethod method : SpringBeans.beanMethods(context)) {
            if (!method.hasBody() || !(method.getReturnType() instanceof ClassType returned)
                    || !returned.getFullyQualifiedName().endsWith(".function.RouterFunction")) {
                continue;
            }
            MvcRoute current = null;
            // route(predicate, handler)'s predicate is built before the call, so before the route starts.
            Set<AbstractInvokeExpr> predicates = new HashSet<>();
            Map<AbstractInvokeExpr, List<String[]>> predicated = new HashMap<>();
            for (Stmt stmt : method.getBody().getStmts()) {
                Locals.invoke(stmt).filter(invoke -> invoke.getMethodSignature().getDeclClassType()
                        .getFullyQualifiedName().equals(MVC_ROUTER_FUNCTIONS) && invoke.getArgCount() == 2)
                        .ifPresent(route -> predicated.put(route, endpoints(method, route.getArg(0), predicates).stream()
                                .filter(endpoint -> endpoint[1] != null).toList()));
            }
            for (Stmt stmt : method.getBody().getStmts()) {
                Optional<AbstractInvokeExpr> found = Locals.invoke(stmt).filter(invoke -> !predicates.contains(invoke));
                if (found.isEmpty()) {
                    continue;
                }
                AbstractInvokeExpr invoke = found.get();
                String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
                String name = invoke.getMethodSignature().getName();
                List<String> args = constants(method, invoke);
                // GatewayRouterFunctions' only methods are its route(..)s: route(id), route() and
                // route(predicate, handler).
                if (owner.equals(MVC_ROUTER_FUNCTIONS)) {
                    if (current != null) {
                        routes.addAll(current.routes());
                    }
                    current = new MvcRoute(args.isEmpty() ? "route" + routes.size() : args.getFirst(),
                            MethodNames.codeRef(method.getSignature(), stmt));
                    current.endpoints.addAll(predicated.getOrDefault(invoke, List.of()));
                    continue;
                }
                if (current == null) {
                    continue;
                }
                Optional<String> first = invoke.getArgCount() == 0 ? Optional.empty()
                        : text(method, invoke.getArg(0), null);
                if (owner.endsWith("RouterFunctions$Builder") && MVC_METHODS.contains(name) && !args.isEmpty()) {
                    current.endpoints.add(new String[] {name, args.getFirst()});
                }
                else if (owner.endsWith("RequestPredicates") && name.equals("path") && !args.isEmpty()) {
                    current.endpoints.add(new String[] {"*", args.getFirst()});
                }
                else if (owner.startsWith(MVC_GATEWAY) && name.equals("uri") && first.isPresent()) {
                    current.uri = first.get();
                }
                else if (owner.startsWith(MVC_GATEWAY) && name.equals("lb") && first.isPresent()) {
                    // LoadBalancerFilterFunctions.lb("users-service"): the service the load balancer picks.
                    current.uri = "lb://" + first.get();
                }
                else if (owner.startsWith(MVC_GATEWAY) && MVC_FILTERS.contains(name)) {
                    current.filters.add(Character.toUpperCase(name.charAt(0)) + name.substring(1) + "="
                            + String.join(", ", args));
                }
            }
            if (current != null) {
                routes.addAll(current.routes());
            }
        }
        return routes;
    }

    /**
     * The method and path pairs a request predicate matches: {@code path("/x")}, {@code GET("/x")},
     * {@code method(HttpMethod.GET)}, and their {@code and(..)} and {@code or(..)}; a predicate on something else
     * ({@code accept(..)}) matches any request it is joined to. The calls it is made of go into {@code calls}.
     */
    private List<String[]> endpoints(JavaSootMethod method, Value predicate, Set<AbstractInvokeExpr> calls) {
        if (!(predicate instanceof Local local) || !(Locals.definition(method.getBody(), local).orElse(null)
                instanceof AbstractInvokeExpr call)) {
            return List.of();
        }
        calls.add(call);
        String owner = call.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        String name = call.getMethodSignature().getName();
        List<String> args = constants(method, call);
        if (owner.endsWith("RequestPredicates")) {
            if (name.equals("method") && call.getArgCount() == 1 && call.getArg(0) instanceof Local value
                    && Locals.definition(method.getBody(), value).orElse(null) instanceof JStaticFieldRef field) {
                return List.<String[]>of(new String[] {field.getFieldSignature().getName(), null});
            }
            return args.isEmpty() || !(name.equals("path") || MVC_METHODS.contains(name)) ? List.of()
                    : List.<String[]>of(new String[] {name.equals("path") ? "*" : name, args.getFirst()});
        }
        if (!(call instanceof AbstractInstanceInvokeExpr joined) || call.getArgCount() != 1
                || !(name.equals("and") || name.equals("or"))) {
            return List.of();
        }
        List<String[]> left = endpoints(method, joined.getBase(), calls);
        List<String[]> right = endpoints(method, call.getArg(0), calls);
        List<String[]> all = new ArrayList<>(left);
        all.addAll(right);
        if (name.equals("or")) {
            return all.stream().filter(endpoint -> endpoint[1] != null).toList();
        }
        List<String> paths = all.stream().map(endpoint -> endpoint[1]).filter(Objects::nonNull).toList();
        List<String> verbs = all.stream().map(endpoint -> endpoint[0]).filter(verb -> !verb.equals("*")).toList();
        List<String[]> endpoints = new ArrayList<>();
        for (String path : paths) {
            for (String verb : verbs.isEmpty() ? List.of("*") : verbs) {
                endpoints.add(new String[] {verb, path});
            }
        }
        return endpoints;
    }

    /**
     * The text a value holds: a constant, the configuration's ({@link ConfiguredValues}), what the lambda it is read
     * in captures where it is created, {@code URI.create(..)}'s, or a concatenation of those.
     */
    private Optional<String> text(JavaSootMethod method, Value value, Captured captured) {
        if (!(value instanceof Local local)) {
            return value instanceof StringConstant constant ? Optional.of(constant.getValue()) : Optional.empty();
        }
        OptionalInt parameter = Locals.parameterIndex(method.getBody(), local);
        if (parameter.isPresent() && captured != null) {
            // The captured values come first, after the instance a lambda that uses this captures.
            int index = parameter.getAsInt() + (method.isStatic() ? 0 : 1);
            return index < captured.creation().getArgCount()
                    ? text(captured.method(), captured.creation().getArg(index), captured.outer()) : Optional.empty();
        }
        Value definition = Locals.definition(method.getBody(), local).orElse(null);
        if (definition instanceof AbstractInvokeExpr call && call.getArgCount() == 1
                && call.getMethodSignature().getName().equals("create")
                && call.getMethodSignature().getDeclClassType().getFullyQualifiedName().equals("java.net.URI")) {
            return text(method, call.getArg(0), captured);
        }
        Optional<List<Object>> parts = definition == null ? Optional.empty()
                : HttpClientEgress.textParts(method, definition);
        if (parts.isPresent()) {
            StringBuilder joined = new StringBuilder();
            for (Object part : parts.get()) {
                Optional<String> text = part instanceof String constant ? Optional.of(constant)
                        : text(method, (Value) part, captured);
                if (text.isEmpty()) {
                    return Optional.empty();
                }
                joined.append(text.get());
            }
            return Optional.of(joined.toString());
        }
        return Optional.ofNullable(configured.of(method, value).value());
    }

    /**
     * A Server MVC route being read: its method and path pairs, its filters and its uri.
     */
    private static final class MvcRoute {
        final String id;
        final CodeRef declaredAt;
        final List<String[]> endpoints = new ArrayList<>();
        final List<String> filters = new ArrayList<>();
        String uri;

        MvcRoute(String id, CodeRef declaredAt) {
            this.id = id;
            this.declaredAt = declaredAt;
        }

        List<Route> routes() {
            return endpoints.stream().map(endpoint -> new Route(id, List.of(endpoint[1]),
                    endpoint[0].equals("*") ? List.of() : List.of(endpoint[0]), uri, filters, declaredAt)).toList();
        }
    }

    /**
     * A call's string and int constants, varargs arrays included.
     */
    private static List<String> constants(JavaSootMethod method, AbstractInvokeExpr invoke) {
        List<String> args = new ArrayList<>();
        for (Value arg : invoke.getArgs()) {
            if (arg instanceof StringConstant constant) {
                args.add(constant.getValue());
            }
            else if (arg instanceof IntConstant number) {
                args.add(String.valueOf(number.getValue()));
            }
            else if (arg instanceof Local array) {
                args.addAll(elements(method, array));
            }
        }
        return args;
    }

    private Optional<JavaSootMethod> lambda(Value value) {
        if (!(value instanceof JDynamicInvokeExpr dynamic)) {
            return Optional.empty();
        }
        for (Value argument : dynamic.getBootstrapArgs()) {
            if (argument instanceof MethodHandle handle && handle.getReferenceSignature() instanceof MethodSignature target
                    && context.isApplication(target.getDeclClassType())) {
                return context.findMethod(target).filter(JavaSootMethod::hasBody);
            }
        }
        return Optional.empty();
    }

    /**
     * The predicate and filter specs' calls in a route lambda, and in the lambdas it passes on.
     */
    private void read(JavaSootMethod method, List<String> paths, List<String> methods, List<String> filters,
            String[] uri, Set<MethodSignature> seen, Captured captured) {
        if (!seen.add(method.getSignature())) {
            return;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition) {
                lambda(definition.getRightOp()).ifPresent(inner -> read(inner, paths, methods, filters, uri, seen,
                        new Captured(method, (JDynamicInvokeExpr) definition.getRightOp(), captured)));
            }
            Optional<AbstractInvokeExpr> found = Locals.invoke(stmt);
            if (found.isEmpty() || !found.get().getMethodSignature().getDeclClassType().getFullyQualifiedName()
                    .startsWith(SPECS)) {
                continue;
            }
            AbstractInvokeExpr invoke = found.get();
            List<String> args = constants(method, invoke);
            String name = invoke.getMethodSignature().getName();
            switch (name) {
                case "path" -> paths.addAll(args);
                case "method" -> args.forEach(arg -> methods.add(arg.toUpperCase(Locale.ROOT)));
                // uri(String) and uri(URI), from a constant, the configuration, or what the lambda captures.
                case "uri" -> text(method, invoke.getArg(0), captured).ifPresent(text -> uri[0] = text);
                case "stripPrefix", "prefixPath", "setPath", "rewritePath", "tokenRelay", "removeRequestHeader",
                        "setRequestHeader", "addRequestHeader" -> filters.add(Character.toUpperCase(name.charAt(0))
                                + name.substring(1) + "=" + String.join(", ", args));
                default -> {
                }
            }
        }
    }

    /**
     * The constants stored into a varargs array: strings, or {@code HttpMethod.GET} by name.
     */
    private static List<String> elements(JavaSootMethod method, Local array) {
        List<String> elements = new ArrayList<>();
        for (Value value : Locals.elements(method.getBody(), array)) {
            if (value instanceof StringConstant text) {
                elements.add(text.getValue());
            }
            else if (value instanceof JStaticFieldRef field && field.getFieldSignature()
                    .getDeclClassType().getFullyQualifiedName().equals(HTTP_METHOD)) {
                elements.add(field.getFieldSignature().getName());
            }
        }
        return elements;
    }
}
