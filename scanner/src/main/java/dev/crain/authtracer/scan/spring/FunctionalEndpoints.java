package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.expr.JNewArrayExpr;
import sootup.core.jimple.common.expr.JNewExpr;
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
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Functional endpoints: {@code RouterFunction} beans, for WebFlux ({@code org.springframework.web.reactive.function
 * .server}) and Spring MVC ({@code org.springframework.web.servlet.function}). Read from
 * {@code RouterFunctions.route().GET("/x/{id}", handler::get)...build()}, with {@code path(..)}/{@code nest(..)}
 * prefixes, from {@code route(GET("/x"), handler::get).andRoute(..)}, and from the Kotlin DSLs
 * {@code router { "/x".nest { GET("/{id}", handler::get) } }} and {@code coRouter { }}. The handler is the method
 * reference or lambda each route runs, or the {@code handle} method of a {@code HandlerFunction} class.
 * <p>
 * Decision 0080: nothing is dropped. A predicate {@code or(..)} (or {@code methods(..)}) registers each alternative;
 * a predicate AuthTracer can't read (a lambda, a custom {@code RequestPredicate}, {@code negate()}, a path that isn't
 * a constant) gives the route what is known of it, at worst every request under its prefix, with an OPAQUE_CONFIG
 * finding; a handler it can't follow keeps the route, with a finding; routes it can't read at all are a finding naming
 * the bean.
 * <p>
 * A route's filters ({@code filter(..)} and {@code before(..)} of a builder, for every route it builds, and
 * {@code RouterFunction#filter(..)}, for every route of the function) run before its handler, outermost first: each
 * is walked before the handler, and one AuthTracer can't follow is a finding.
 */
@Supports(Feature.HTTP_ENDPOINTS)
final class FunctionalEndpoints {

    private static final Set<String> PACKAGES = Set.of("org.springframework.web.reactive.function.server.",
            "org.springframework.web.servlet.function.");
    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
    /**
     * Predicates that don't narrow the method or the path ({@code accept(..)}, {@code headers(..)}, ...): every request
     * their route's path and method name may match them.
     */
    private static final Set<String> CONTENT_PREDICATES = Set.of("all", "accept", "contentType", "headers",
            "queryParam", "version", "pathExtension");
    /**
     * A builder's calls that filter the requests of every route it builds, before the handler: {@code before(..)} is
     * a filter that changes the request ({@code after(..)} and {@code onError(..)} run once the handler has).
     */
    private static final Set<String> FILTERS = Set.of("filter", "before");
    private static final String HTTP_METHOD = "org.springframework.http.HttpMethod";
    private static final String STRING = "java.lang.String";
    private static final String KOTLIN_FUNCTION = "kotlin.jvm.functions.Function";
    private static final String SUSPEND_LAMBDA = "kotlin.coroutines.jvm.internal.SuspendLambda";
    private static final String GATEWAY = "org.springframework.cloud.gateway.server.mvc.";
    private static final String NOT_CONSTANT = "a path that isn't a constant";
    private static final String NOT_CONSTANT_METHOD = "an HTTP method that isn't a constant";

    /**
     * A builder in progress, the routes added to it so far, and what was added that AuthTracer can't read:
     * {@code build()} returns them, so they get the prefix of wherever the {@code RouterFunction} ends up
     * ({@code nest(path("/api"), route().GET(..).build())}).
     */
    private record Builder(List<Pending> routes, List<String> unread, List<Object> filters) {

        Builder() {
            this(new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
        }

        /**
         * Spring Framework 7.0.9's {@code RouterFunctionBuilder#build}: its filters, in the order added, around every
         * route it has, whenever it was added.
         */
        Routes build() {
            return new Routes(routes.stream().map(route -> route.filtered(filters)).toList(), List.copyOf(unread));
        }
    }

    /**
     * One way a request predicate matches: an HTTP method ({@code *} for any), a path pattern ({@code null} for any),
     * and what else it asks that AuthTracer can't read, which may let fewer requests through.
     */
    private record Alternative(String method, String pattern, List<String> unread) {

        Alternative and(Alternative other) {
            return new Alternative(method.equals("*") ? other.method() : method,
                    pattern == null ? other.pattern() : pattern, concat(unread, other.unread()));
        }

        /**
         * This route's alternative nested under a prefix's: its path is relative to the prefix's.
         */
        Alternative under(Alternative prefix) {
            return new Alternative(method.equals("*") ? prefix.method() : method, RequestMappings.join(
                    prefix.pattern() == null ? "" : prefix.pattern(), pattern == null ? "/**" : pattern),
                    concat(prefix.unread(), unread));
        }
    }

    /**
     * A request predicate: it matches when one of its alternatives does.
     */
    private record Predicate(List<Alternative> alternatives) {

        static Predicate of(String method, String pattern) {
            return new Predicate(List.of(new Alternative(method, pattern, List.of())));
        }

        /**
         * A predicate AuthTracer can't read: as far as it knows, it matches any request.
         */
        static Predicate unread(String what) {
            return new Predicate(List.of(new Alternative("*", null, List.of(what))));
        }

        Predicate and(Predicate other) {
            return new Predicate(alternatives.stream().flatMap(mine -> other.alternatives().stream().map(mine::and))
                    .toList());
        }

        Predicate or(Predicate other) {
            return new Predicate(concat(alternatives, other.alternatives()));
        }
    }

    private record Text(String value) {
    }

    private record MethodValue(String name) {
    }

    /**
     * The values stored into an array, as a varargs call ({@code methods(GET, POST)}) passes them.
     */
    private record Elements(List<Object> values) {
    }

    private record Lambda(MethodSignature target, List<Object> captured) {
    }

    /**
     * A {@code HandlerFunction} class's instance: its {@code handle(ServerRequest)} handles the route.
     */
    private record HandlerClass(ClassType type) {
    }

    /**
     * A {@code HandlerFilterFunction} class's instance: its {@code filter(ServerRequest, HandlerFunction)} runs before
     * the routes it filters.
     */
    private record FilterClass(ClassType type) {
    }

    /**
     * A value AuthTracer can't read, described for a finding.
     */
    private record Unread(String what) {
    }

    /**
     * A route not yet registered: its prefix is known only where the {@code RouterFunction} it is in ends up.
     */
    private record Pending(Predicate predicate, Object handler, List<Object> filters) {

        Pending(Predicate predicate, Object handler) {
            this(predicate, handler, List.of());
        }

        Pending under(Predicate prefix) {
            return new Pending(new Predicate(prefix.alternatives().stream().flatMap(outer -> predicate.alternatives()
                    .stream().map(inner -> inner.under(outer))).toList()), handler, filters);
        }

        /**
         * The route with filters around its own: they run first.
         */
        Pending filtered(List<Object> outer) {
            return outer.isEmpty() ? this : new Pending(predicate, handler, concat(outer, filters));
        }
    }

    /**
     * A {@code RouterFunction} from {@code route(..)} or a builder's {@code build()}: {@code andRoute(..)},
     * {@code and(..)} and {@code andNest(..)} add to it, static {@code nest(..)} prefixes it; registered where a bean
     * method returns it. {@code unread} names what was added to it that AuthTracer can't read.
     */
    private record Routes(List<Pending> pending, List<String> unread) {

        static Routes none() {
            return new Routes(List.of(), List.of());
        }

        Routes with(Routes other) {
            return new Routes(concat(pending, other.pending()), concat(unread, other.unread()));
        }

        Routes under(Predicate prefix) {
            return new Routes(pending.stream().map(route -> route.under(prefix)).toList(), unread);
        }

        Routes filtered(List<Object> outer) {
            return new Routes(pending.stream().map(route -> route.filtered(outer)).toList(), unread);
        }
    }

    /**
     * How deep helper methods that build routes are followed.
     */
    private static final int MAX_HELPERS = 4;

    private final ScanContext context;
    private final SpringBeans beans;
    private final List<Finding> findings = new ArrayList<>();

    FunctionalEndpoints(ScanContext context, SpringBeans beans) {
        this.context = context;
        this.beans = beans;
    }

    List<Finding> findings() {
        return findings;
    }

    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        for (JavaSootMethod method : SpringBeans.beanMethods(context)) {
            if (!method.hasBody() || !(method.getReturnType() instanceof ClassType returned) || !isRouter(returned)
                    || gateway(method)) {
                continue;
            }
            String bean = MethodNames.key(method.getSignature());
            CodeRef at = MethodNames.codeRef(method.getSignature());
            Object built = interpret(method, Map.of(), 0);
            if (!(built instanceof Routes routes)) {
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RouterFunction bean " + bean + " builds its"
                        + " routes in a way AuthTracer can't read (" + describe(built) + "): the endpoints it serves"
                        + " are not in the graph", at));
                continue;
            }
            routes.pending().forEach(route -> register(method, route, mappings));
            if (!routes.unread().isEmpty()) {
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RouterFunction bean " + bean + " also has"
                        + " routes AuthTracer can't read (" + String.join("; ", routes.unread().stream().distinct()
                                .toList()) + "): the endpoints they serve are not in the graph", at));
            }
        }
        return mappings;
    }

    /**
     * Spring Cloud Gateway Server MVC's routes are {@code RouterFunction} beans too, which {@link GatewayRoutes} reads
     * (decision 0043).
     */
    private static boolean gateway(JavaSootMethod method) {
        return method.getBody().getStmts().stream().flatMap(stmt -> Locals.invoke(stmt).stream())
                .anyMatch(invoke -> invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                        .startsWith(GATEWAY));
    }

    private static boolean isRouter(ClassType type) {
        return PACKAGES.stream().anyMatch(pkg -> type.getFullyQualifiedName().equals(pkg + "RouterFunction"));
    }

    private static boolean ownedHere(String owner) {
        return PACKAGES.stream().anyMatch(owner::startsWith);
    }

    private static <T> List<T> concat(List<T> first, List<T> second) {
        return second.isEmpty() ? first : first.isEmpty() ? second
                : Stream.concat(first.stream(), second.stream()).toList();
    }

    private Object interpret(JavaSootMethod method, Map<Integer, Object> parameters, int depth) {
        Map<Local, Object> values = new HashMap<>();
        Object returned = null;
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof Local local) {
                Object value = evaluate(definition.getRightOp(), values, parameters, depth);
                if (value != null) {
                    values.put(local, value);
                }
            }
            else if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof JArrayRef
                    element && values.get(element.getBase()) instanceof Elements array) {
                array.values().add(evaluate(definition.getRightOp(), values, parameters, depth));
            }
            else if (stmt.isInvokableStmt()) {
                stmt.asInvokableStmt().getInvokeExpr().ifPresent(invoke -> call(invoke, values, depth));
            }
            if (stmt instanceof JReturnStmt result && result.getOp() instanceof Local local) {
                returned = values.get(local);
            }
        }
        return returned;
    }

    private Object evaluate(Value right, Map<Local, Object> values, Map<Integer, Object> parameters, int depth) {
        if (right instanceof JParameterRef parameter) {
            // A bean method's parameters are beans Spring injects, found by type.
            return parameters.containsKey(parameter.getIndex()) ? parameters.get(parameter.getIndex())
                    : depth == 0 ? injected(parameter.getType()) : null;
        }
        if (right instanceof Local local) {
            return values.get(local);
        }
        if (right instanceof StringConstant constant) {
            return new Text(constant.getValue());
        }
        if (right instanceof JStaticFieldRef field
                && field.getFieldSignature().getDeclClassType().getFullyQualifiedName().equals(HTTP_METHOD)) {
            return new MethodValue(field.getFieldSignature().getName());
        }
        if (right instanceof JStaticFieldRef field && context.isApplication(field.getFieldSignature()
                .getDeclClassType())) {
            Object constant = constant(field, depth);
            if (constant != null) {
                return constant;
            }
        }
        if (right instanceof JFieldRef field) {
            return typed(field.getFieldSignature().getType(), "the field " + field.getFieldSignature().getName());
        }
        if (right instanceof JCastExpr cast) {
            return cast.getOp() instanceof Local local ? values.get(local) : null;
        }
        if (right instanceof JNewArrayExpr) {
            return new Elements(new ArrayList<>());
        }
        if (right instanceof JNewExpr created) {
            return kotlinFunction(created.getType()).map(Object.class::cast)
                    .orElseGet(() -> typed(created.getType(), "a new " + created.getType().getFullyQualifiedName()));
        }
        if (right instanceof JDynamicInvokeExpr dynamic) {
            for (Value argument : dynamic.getBootstrapArgs()) {
                if (argument instanceof MethodHandle handle && handle.getReferenceSignature() instanceof MethodSignature
                        target) {
                    return new Lambda(target, dynamic.getArgs().stream().map(arg -> argument(arg, values)).toList());
                }
            }
            return null;
        }
        if (right instanceof AbstractInvokeExpr invoke) {
            return call(invoke, values, depth);
        }
        return null;
    }

    /**
     * A static field's value, as its class's initializer sets it: {@code static final RequestPredicate JSON =
     * accept(APPLICATION_JSON)}.
     */
    private Object constant(JStaticFieldRef field, int depth) {
        Optional<JavaSootMethod> initializer = context.findClass(field.getFieldSignature().getDeclClassType())
                .flatMap(cls -> cls.getMethods().stream().filter(method -> method.getName().equals("<clinit>")
                        && method.hasBody()).findFirst());
        if (initializer.isEmpty() || depth >= MAX_HELPERS) {
            return null;
        }
        Map<Local, Object> values = new HashMap<>();
        for (Stmt stmt : initializer.get().getBody().getStmts()) {
            if (stmt instanceof AbstractDefinitionStmt definition && definition.getLeftOp() instanceof Local local) {
                Object value = evaluate(definition.getRightOp(), values, Map.of(), depth + 1);
                if (value != null) {
                    values.put(local, value);
                }
            }
            else if (stmt instanceof AbstractDefinitionStmt definition
                    && definition.getLeftOp() instanceof JStaticFieldRef assigned
                    && assigned.getFieldSignature().equals(field.getFieldSignature())) {
                return definition.getRightOp() instanceof Local local ? values.get(local) : null;
            }
        }
        return null;
    }

    /**
     * What a value of a type is, when nothing else says: an instance of a {@code HandlerFunction} class handles
     * routes; other request predicates and routes can't be read.
     */
    private Object typed(Type type, String what) {
        if (!(type instanceof ClassType classType)) {
            return null;
        }
        String name = MethodNames.simpleName(classType.getFullyQualifiedName());
        if (context.isApplication(classType) && handlerFunction(classType)) {
            return new HandlerClass(classType);
        }
        if (context.isApplication(classType) && PACKAGES.stream().anyMatch(pkg -> SpringBeans.assignable(context,
                classType, Set.of(pkg + "HandlerFilterFunction")))) {
            return new FilterClass(classType);
        }
        if (predicateType(classType)) {
            return new Unread(classType.getFullyQualifiedName().endsWith(".RequestPredicate")
                    ? "a RequestPredicate from " + what : "the custom RequestPredicate " + name);
        }
        if (PACKAGES.stream().anyMatch(pkg -> SpringBeans.assignable(context, classType, Set.of(pkg + "RouterFunction")))) {
            return new Unread(isRouter(classType) ? "a RouterFunction from " + what
                    : "the custom RouterFunction " + name);
        }
        return null;
    }

    /**
     * A bean method's parameter, a bean Spring finds by its type: a {@code HandlerFunction} bean of the application's
     * when it has only one. (A {@code RouterFunction} bean given to another is registered on its own too, but the
     * other may nest it under a prefix, so its routes there are unread.)
     */
    private Object injected(Type type) {
        if (type instanceof ClassType classType && !context.isApplication(classType) && handlerFunction(classType)) {
            List<ClassType> candidates = context.applicationClasses().stream().map(JavaSootClass::getType)
                    .filter(candidate -> beans.isBean(candidate) && SpringBeans.assignable(context, candidate,
                            Set.of(classType.getFullyQualifiedName())))
                    .toList();
            return candidates.size() == 1 ? new HandlerClass(candidates.getFirst())
                    : new Unread("one of the application's " + candidates.size() + " HandlerFunction beans");
        }
        return typed(type, "a bean method parameter");
    }

    private boolean handlerFunction(ClassType type) {
        return PACKAGES.stream().anyMatch(pkg -> SpringBeans.assignable(context, type, Set.of(pkg + "HandlerFunction")));
    }

    private boolean predicateType(ClassType type) {
        return PACKAGES.stream().anyMatch(pkg -> SpringBeans.assignable(context, type, Set.of(pkg + "RequestPredicate")));
    }

    private Object call(AbstractInvokeExpr invoke, Map<Local, Object> values, int depth) {
        String owner = invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName();
        if (!ownedHere(owner)) {
            Object built = helper(invoke, values, depth);
            String what = "what " + MethodNames.key(invoke.getMethodSignature()) + " returns";
            Object typed = built != null ? built : typed(invoke.getMethodSignature().getType(), what);
            return typed != null || !(invoke.getMethodSignature().getType() instanceof ClassType) ? typed
                    : new Unread(what);
        }
        String name = invoke.getMethodSignature().getName();
        List<Object> args = invoke.getArgs().stream().map(arg -> argument(arg, values)).toList();
        Object receiver = invoke instanceof AbstractInstanceInvokeExpr instance ? values.get(instance.getBase()) : null;
        if (owner.endsWith(".RequestPredicates")) {
            return predicate(name, args);
        }
        if (owner.endsWith("RouterFunctionDslKt") && (name.equals("router") || name.equals("coRouter"))
                && args.size() == 1 && args.getFirst() instanceof Lambda routes) {
            // Kotlin: router { ... }, whose lambda's receiver is the DSL, which takes routes like a builder.
            return nested(routes);
        }
        if (receiver instanceof Predicate predicate) {
            return switch (name) {
                case "and" -> predicate.and(predicateOf(args.getFirst()));
                case "or" -> predicate.or(predicateOf(args.getFirst()));
                case "negate" -> Predicate.unread("negate()");
                default -> predicate;
            };
        }
        if (owner.endsWith(".RouterFunctions") && receiver == null) {
            return switch (name) {
                case "route" -> args.isEmpty() ? new Builder()
                        : new Routes(List.of(new Pending(predicateOf(args.get(0)), args.get(1))), List.of());
                // nest(path("/api"), routes): the routes under the predicate's path.
                case "nest" -> routesOf(args.get(1)).under(predicateOf(args.get(0)));
                // Static resources, served by no handler of the application's.
                case "resources", "resource" -> Routes.none();
                default -> null;
            };
        }
        if (receiver instanceof Routes routes) {
            return switch (name) {
                case "andRoute" -> routes.with(new Routes(List.of(new Pending(predicateOf(args.get(0)),
                        args.get(1))), List.of()));
                case "and", "andOther" -> routes.with(routesOf(args.getFirst()));
                case "andNest" -> routes.with(routesOf(args.get(1)).under(predicateOf(args.get(0))));
                case "filter" -> args.size() == 1 ? routes.filtered(List.of(filterOf(args.getFirst()))) : routes;
                default -> routes;
            };
        }
        if (receiver instanceof Builder builder) {
            if (name.equals("build")) {
                return builder.build();
            }
            if (owner.endsWith("RouterFunctionDsl")) {
                return dslCall(builder, invoke.getMethodSignature(), args);
            }
            return builderCall(builder, invoke.getMethodSignature(), args);
        }
        return null;
    }

    /**
     * An application method that builds a {@code RouterFunction}: its routes, as it returns them.
     */
    private Object helper(AbstractInvokeExpr invoke, Map<Local, Object> values, int depth) {
        if (!(invoke.getMethodSignature().getType() instanceof ClassType returned)
                || !isRouter(returned) || !context.isApplication(invoke.getMethodSignature().getDeclClassType())) {
            return null;
        }
        if (depth >= MAX_HELPERS) {
            context.limit("Following the helper methods that build routes", MAX_HELPERS,
                    MethodNames.key(invoke.getMethodSignature()));
            return null;
        }
        Optional<JavaSootMethod> method = context.findMethod(invoke.getMethodSignature())
                .filter(JavaSootMethod::hasBody);
        if (method.isEmpty()) {
            return null;
        }
        Map<Integer, Object> parameters = new HashMap<>();
        for (int i = 0; i < invoke.getArgCount(); i++) {
            Object argument = argument(invoke.getArg(i), values);
            if (argument != null) {
                parameters.put(i, argument);
            }
        }
        return interpret(method.get(), parameters, depth + 1);
    }

    /**
     * {@code RouterFunctions.Builder}'s calls.
     */
    private Object builderCall(Builder builder, MethodSignature called, List<Object> args) {
        String name = called.getName();
        if (METHODS.contains(name) || name.equals("route")) {
            // GET(handler), GET(pattern, handler), GET(predicate, handler), GET(pattern, predicate, handler),
            // route(predicate, handler)
            builder.routes().add(route(name.equals("route") ? "*" : name, called, args));
        }
        else if ((name.equals("path") || name.equals("nest")) && args.size() == 2) {
            // path(pattern, builder -> ..), nest(predicate, () -> routes)
            Predicate prefix = called.getParameterTypes().getFirst().toString().equals(STRING)
                    ? pathPredicate(args.getFirst()) : predicateOf(args.getFirst());
            Routes nested = nestedOf(args.getLast());
            builder.routes().addAll(nested.under(prefix).pending());
            builder.unread().addAll(nested.unread());
        }
        else if (name.equals("add") && args.size() == 1) {
            Routes added = routesOf(args.getFirst());
            builder.routes().addAll(added.pending());
            builder.unread().addAll(added.unread());
        }
        else if (FILTERS.contains(name) && args.size() == 1) {
            builder.filters().add(filterOf(args.getFirst()));
        }
        return builder;
    }

    /**
     * The Kotlin DSL's calls ({@code RouterFunctionDsl}, {@code CoRouterFunctionDsl}): predicates
     * ({@code GET("/x")}, {@code path(..)}, {@code accept(..)}, {@code and}/{@code or}/{@code not}), routes
     * ({@code GET("/x", handler)}, {@code accept(json, handler)}, {@code "/x"(handler)}, {@code predicate(handler)}),
     * {@code nest} and {@code add}.
     */
    private Object dslCall(Builder builder, MethodSignature called, List<Object> args) {
        String name = called.getName();
        if (called.getType() instanceof ClassType returned && predicateType(returned)) {
            return switch (name) {
                case "and" -> dslPredicate(args.get(0)).and(dslPredicate(args.get(1)));
                case "or" -> dslPredicate(args.get(0)).or(dslPredicate(args.get(1)));
                case "not" -> Predicate.unread("not(..)");
                default -> predicate(name, args);
            };
        }
        if (name.equals("nest") && args.size() == 2) {
            Routes nested = nestedOf(args.getLast());
            builder.routes().addAll(nested.under(dslPredicate(args.getFirst())).pending());
            builder.unread().addAll(nested.unread());
        }
        else if (METHODS.contains(name)) {
            builder.routes().add(route(name, called, args));
        }
        else if (name.equals("invoke") && args.size() == 2) {
            builder.routes().add(new Pending(dslPredicate(args.getFirst()), args.getLast()));
        }
        else if (Set.of("path", "method", "accept", "contentType", "headers", "pathExtension", "queryParam")
                .contains(name) && !args.isEmpty()) {
            builder.routes().add(new Pending(predicate(name, args.subList(0, args.size() - 1)), args.getLast()));
        }
        else if (name.equals("add") && args.size() == 1) {
            Routes added = routesOf(args.getFirst());
            builder.routes().addAll(added.pending());
            builder.unread().addAll(added.unread());
        }
        else if (FILTERS.contains(name) && args.size() == 1) {
            builder.filters().add(filterOf(args.getFirst()));
        }
        return builder;
    }

    /**
     * A filter as given: a lambda or method reference, an instance of the application's {@code HandlerFilterFunction}
     * class, or what AuthTracer can't follow.
     */
    private static Object filterOf(Object value) {
        return value instanceof Lambda || value instanceof FilterClass ? value
                : new Unread(describe(value));
    }

    /**
     * A route of a builder or the DSL from its arguments, by their declared types: the {@code String} pattern, the
     * {@code RequestPredicate}, and last the handler.
     */
    private static Pending route(String method, MethodSignature called, List<Object> args) {
        Predicate predicate = Predicate.of(method, null);
        List<Type> types = called.getParameterTypes();
        for (int i = 0; i < args.size() - 1 && i < types.size(); i++) {
            predicate = predicate.and(types.get(i).toString().equals(STRING) ? pathPredicate(args.get(i))
                    : predicateOf(args.get(i)));
        }
        return new Pending(predicate, args.getLast());
    }

    /**
     * The Kotlin DSL takes a path where it takes a predicate: {@code "/x" and accept(..)}, {@code "/x".nest { }}.
     */
    private static Predicate dslPredicate(Object value) {
        return value instanceof Text ? pathPredicate(value) : predicateOf(value);
    }

    private static Predicate pathPredicate(Object value) {
        return value instanceof Text text ? Predicate.of("*", text.value())
                : new Predicate(List.of(new Alternative("*", null, List.of(NOT_CONSTANT))));
    }

    private static Predicate predicateOf(Object value) {
        if (value instanceof Predicate predicate) {
            return predicate;
        }
        return Predicate.unread(describe(value));
    }

    private static Routes routesOf(Object value) {
        return value instanceof Routes routes ? routes
                : new Routes(List.of(), List.of(describe(value)));
    }

    private static String describe(Object value) {
        return switch (value) {
            case Unread unread -> unread.what();
            case FilterClass filter -> filter.type().getFullyQualifiedName();
            // The findings name it by the method it is written in (decision 0089).
            case Lambda lambda -> MethodNames.key(lambda.target());
            case null, default -> "a value AuthTracer can't follow";
        };
    }

    private Routes nestedOf(Object value) {
        return value instanceof Lambda lambda ? nested(lambda)
                : new Routes(List.of(), List.of("nested routes from " + describe(value)));
    }

    /**
     * The routes of a {@code path(..)}/{@code nest(..)} lambda (or the Kotlin DSL's): a {@code Consumer<Builder>}
     * adds them to the builder it is given, a {@code Supplier<RouterFunction>} returns them.
     */
    private Routes nested(Lambda lambda) {
        Optional<JavaSootMethod> body = context.findMethod(lambda.target()).filter(JavaSootMethod::hasBody);
        if (body.isEmpty()) {
            return new Routes(List.of(), List.of("nested routes from " + describe(lambda)));
        }
        Map<Integer, Object> parameters = new HashMap<>();
        for (int i = 0; i < lambda.captured().size(); i++) {
            if (lambda.captured().get(i) != null) {
                parameters.put(i, lambda.captured().get(i));
            }
        }
        Builder builder = new Builder();
        if (body.get().getParameterCount() > lambda.captured().size()) {
            parameters.put(body.get().getParameterCount() - 1, builder);
        }
        Object returned = interpret(body.get(), parameters, 0);
        Routes added = builder.build();
        return returned instanceof Routes supplied ? added.with(supplied) : added;
    }

    /**
     * A Kotlin function object compiled to a class: a callable reference ({@code handler::list}, which Kotlin
     * compiles to a class when it adapts or suspends) or a suspend lambda. Its handler is the application method a
     * reference calls, else the class's own body ({@code invokeSuspend} for a suspend lambda).
     */
    private Optional<Lambda> kotlinFunction(ClassType type) {
        Optional<JavaSootClass> cls = context.isApplication(type) ? context.findClass(type) : Optional.empty();
        if (cls.isEmpty() || !isKotlinFunction(type)) {
            return Optional.empty();
        }
        Optional<JavaSootMethod> body = cls.get().getMethods().stream()
                .filter(method -> method.hasBody() && method.getName().equals("invokeSuspend")).findFirst()
                .or(() -> cls.get().getMethods().stream()
                        .filter(method -> method.hasBody() && method.getName().equals("invoke"))
                        .max(Comparator.comparing((JavaSootMethod method) -> !method.getParameterTypes()
                                .stream().allMatch(parameter -> parameter.toString().equals("java.lang.Object")))));
        if (body.isEmpty()) {
            return Optional.empty();
        }
        List<MethodSignature> called = body.get().getBody().getStmts().stream()
                .flatMap(stmt -> Locals.invoke(stmt).stream())
                .map(AbstractInvokeExpr::getMethodSignature)
                .filter(signature -> context.isApplication(signature.getDeclClassType())
                        && !signature.getDeclClassType().equals(type) && !signature.getName().equals("<init>"))
                .distinct().toList();
        return Optional.of(new Lambda(called.size() == 1 ? called.getFirst() : body.get().getSignature(), List.of()));
    }

    private boolean isKotlinFunction(ClassType type) {
        List<ClassType> chain = new ArrayList<>(List.of(type));
        chain.addAll(context.superClassesOf(type));
        return chain.stream().anyMatch(candidate -> candidate.getFullyQualifiedName().equals(SUSPEND_LAMBDA)
                || context.interfacesOf(candidate).stream().anyMatch(implemented -> implemented
                        .getFullyQualifiedName().startsWith(KOTLIN_FUNCTION)));
    }

    /**
     * {@code RequestPredicates}' factories (and the Kotlin DSL's): the method and path they match.
     */
    private static Predicate predicate(String name, List<Object> args) {
        if (METHODS.contains(name)) {
            return Predicate.of(name, null).and(pathPredicate(args.getFirst()));
        }
        return switch (name) {
            case "path" -> pathPredicate(args.getFirst());
            case "method" -> args.getFirst() instanceof MethodValue method ? Predicate.of(method.name(), null)
                    : Predicate.unread(NOT_CONSTANT_METHOD);
            case "methods" -> args.getFirst() instanceof Elements methods && !methods.values().isEmpty()
                    && methods.values().stream().allMatch(MethodValue.class::isInstance)
                            ? new Predicate(methods.values().stream().map(method -> new Alternative(
                                    ((MethodValue) method).name(), null, List.of())).toList())
                            : Predicate.unread(NOT_CONSTANT_METHOD);
            default -> CONTENT_PREDICATES.contains(name) ? Predicate.of("*", null)
                    : Predicate.unread("RequestPredicates." + name + "(..)");
        };
    }

    /**
     * One Ingress per alternative of the route's predicate, handled by its handler, with a finding for what
     * AuthTracer can't read of either.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void register(JavaSootMethod bean, Pending route, List<RequestMappings.Mapping> mappings) {
        Optional<JavaSootMethod> handler = handler(route.handler());
        ClassType receiver = route.handler() instanceof HandlerClass handlerClass ? handlerClass.type() : null;
        Optional<JavaSootMethod> runs = handler.or(() -> handlerFunction(bean));
        CodeRef at = MethodNames.codeRef(bean.getSignature());
        List<JavaSootMethod> filters = new ArrayList<>();
        List<String> unfollowed = new ArrayList<>();
        for (Object filter : route.filters()) {
            filter(filter).ifPresentOrElse(filters::add, () -> unfollowed.add(describe(filter)));
        }
        for (Alternative alternative : route.predicate().alternatives()) {
            String path = RequestMappings.join("", alternative.pattern() == null ? "/**" : alternative.pattern());
            String method = alternative.method().toUpperCase(Locale.ROOT);
            String endpoint = method + " " + path;
            if (!alternative.unread().isEmpty()) {
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RouterFunction bean "
                        + MethodNames.key(bean.getSignature()) + " has a route whose request predicate AuthTracer"
                        + " can't read (" + String.join("; ", alternative.unread().stream().distinct().toList())
                        + "): it is shown as " + endpoint + ", every request it may let through", at));
            }
            if (handler.isEmpty()) {
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RouterFunction bean "
                        + MethodNames.key(bean.getSignature()) + " routes " + endpoint + " to a handler AuthTracer"
                        + " can't follow (" + describe(route.handler()) + "): what it checks and calls is not in the"
                        + " graph", at));
            }
            if (!unfollowed.isEmpty()) {
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The RouterFunction bean "
                        + MethodNames.key(bean.getSignature()) + " runs " + endpoint + " through a filter AuthTracer"
                        + " can't follow (" + String.join("; ", unfollowed.stream().distinct().toList()) + "): what"
                        + " it checks before the handler is not in the graph", at));
            }
            if (runs.isEmpty()) {
                continue;
            }
            Ingress ingress = Ingress.of(method, path, handler.isPresent()
                    ? MethodNames.codeRef(runs.get().getSignature()) : at);
            Optional<Payload> response = handler.flatMap(this::response);
            RequestMappings.Mapping mapping = new RequestMappings.Mapping(response.map(ingress::withResponse)
                    .orElse(ingress), runs.get(), true).withFilters(filters);
            mappings.add(receiver == null ? mapping : mapping.onReceiver(receiver));
        }
    }

    /**
     * The method a route's handler runs: the lambda's or method reference's target, or a {@code HandlerFunction}
     * class's {@code handle(ServerRequest)}, inherited or its own.
     */
    private Optional<JavaSootMethod> handler(Object handler) {
        if (handler instanceof Lambda lambda) {
            return context.findMethod(lambda.target()).filter(JavaSootMethod::hasBody);
        }
        if (handler instanceof HandlerClass handlerClass) {
            List<ClassType> chain = new ArrayList<>(List.of(handlerClass.type()));
            chain.addAll(context.superClassesOf(handlerClass.type()));
            return chain.stream().filter(context::isApplication).flatMap(type -> context.findClass(type).stream())
                    .flatMap(cls -> cls.getMethods().stream())
                    .filter(method -> method.getName().equals("handle") && method.hasBody() && !method.isStatic()
                            && method.getParameterCount() == 1 && method.getParameterTypes().getFirst().toString()
                                    .endsWith(".ServerRequest"))
                    .min(Comparator.comparing(method -> method.getReturnType().toString().equals("java.lang.Object")));
        }
        return Optional.empty();
    }

    /**
     * The method a filter runs: the lambda's or method reference's target, or a {@code HandlerFilterFunction} class's
     * {@code filter(ServerRequest, HandlerFunction)}, inherited or its own.
     */
    private Optional<JavaSootMethod> filter(Object filter) {
        if (filter instanceof Lambda lambda) {
            return context.findMethod(lambda.target()).filter(JavaSootMethod::hasBody);
        }
        if (filter instanceof FilterClass filterClass) {
            List<ClassType> chain = new ArrayList<>(List.of(filterClass.type()));
            chain.addAll(context.superClassesOf(filterClass.type()));
            return chain.stream().filter(context::isApplication).flatMap(type -> context.findClass(type).stream())
                    .flatMap(cls -> cls.getMethods().stream())
                    .filter(method -> method.getName().equals("filter") && method.hasBody() && !method.isStatic()
                            && method.getParameterCount() == 2 && method.getParameterTypes().getFirst().toString()
                                    .endsWith(".ServerRequest"))
                    .min(Comparator.comparing(method -> method.getReturnType().toString().equals("java.lang.Object")));
        }
        return Optional.empty();
    }

    /**
     * {@code HandlerFunction#handle} of the bean's stack: what a route whose handler AuthTracer can't follow runs, as
     * far as it knows.
     */
    private Optional<JavaSootMethod> handlerFunction(JavaSootMethod bean) {
        String pkg = ((ClassType) bean.getReturnType()).getPackageName().getName();
        String response = pkg.contains(".reactive.") ? "reactor.core.publisher.Mono" : pkg + ".ServerResponse";
        return context.findMethod(context.view().getIdentifierFactory().getMethodSignature(
                context.type(pkg + ".HandlerFunction"), "handle", response, List.of(pkg + ".ServerRequest")));
    }

    /**
     * The body type: {@code bodyValue(x)} with an application type, or {@code body(publisher, Type.class)}, in the
     * handler or a lambda it passes on (often {@code flatMap(x -> ServerResponse.ok().bodyValue(..))}).
     */
    private Optional<Payload> response(JavaSootMethod handler) {
        return response(handler, 2);
    }

    private Optional<Payload> response(JavaSootMethod handler, int depth) {
        for (Stmt stmt : handler.getBody().getStmts()) {
            if (depth > 1 && stmt instanceof AbstractDefinitionStmt definition
                    && definition.getRightOp() instanceof JDynamicInvokeExpr dynamic) {
                for (Value argument : dynamic.getBootstrapArgs()) {
                    if (argument instanceof MethodHandle handle && handle.getReferenceSignature() instanceof
                            MethodSignature target && context.isApplication(target.getDeclClassType())) {
                        Optional<Payload> nested = context.findMethod(target).filter(JavaSootMethod::hasBody)
                                .flatMap(lambda -> response(lambda, depth - 1));
                        if (nested.isPresent()) {
                            return nested;
                        }
                    }
                }
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isPresent() && invoke.get().getMethodSignature().getName().equals(handler.getName()
                    + "$suspendImpl")) {
                // An open Kotlin suspend function's body is its static $suspendImpl.
                Optional<Payload> body = context.findMethod(invoke.get().getMethodSignature())
                        .filter(JavaSootMethod::hasBody).flatMap(impl -> response(impl, depth));
                if (body.isPresent()) {
                    return body;
                }
            }
            if (invoke.isEmpty() || !ownedHere(invoke.get().getMethodSignature().getDeclClassType()
                    .getFullyQualifiedName())) {
                continue;
            }
            String name = invoke.get().getMethodSignature().getName();
            if (name.equals("bodyValue") && invoke.get().getArgCount() == 1
                    && invoke.get().getArg(0).getType() instanceof ClassType type && context.isApplication(type)) {
                return Optional.of(new Payload(type.getFullyQualifiedName(), false));
            }
            if (name.equals("bodyValueAndAwait") && invoke.get().getArgCount() == 3
                    && invoke.get().getArg(1).getType() instanceof ClassType type && context.isApplication(type)) {
                // Kotlin: builder.bodyValueAndAwait(value), an extension function (builder, value, continuation).
                return Optional.of(new Payload(type.getFullyQualifiedName(), false));
            }
            if (name.equals("body") && invoke.get().getArgCount() == 2
                    && invoke.get().getArg(1) instanceof ClassConstant type) {
                String descriptor = type.getValue();
                boolean many = invoke.get().getArg(0).getType().toString().equals("reactor.core.publisher.Flux");
                return Optional.of(new Payload(descriptor.substring(1, descriptor.length() - 1).replace('/', '.'),
                        many));
            }
        }
        return Optional.empty();
    }

    private static Object argument(Immediate argument, Map<Local, Object> values) {
        if (argument instanceof StringConstant constant) {
            return new Text(constant.getValue());
        }
        return argument instanceof Local local ? values.get(local) : null;
    }
}
