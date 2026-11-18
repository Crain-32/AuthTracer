package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.CallTraversal;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.core.jimple.common.Immediate;
import sootup.core.jimple.common.Local;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0050: plain WebSocket handlers, registered with {@code registry.addHandler(handler, "/ws")} in a
 * {@code WebSocketConfigurer}. Each is an Ingress {@code WEBSOCKET /ws} handled by its {@code handleTextMessage}
 * (or {@code handleBinaryMessage}, {@code handleMessage}), behind its handshake ({@code GET /ws}), which the HTTP
 * rules check. Messages arrive on the container's threads, where no {@code SecurityContext} is set (only STOMP has
 * Spring Security's channel interceptor; a plain handler gets the handshake's user as the session's principal), so the
 * method checks a handler reaches have no caller ({@link NoCaller}).
 * <p>
 * WebFlux maps its {@code WebSocketHandler}s by URL in a {@code SimpleUrlHandlerMapping} bean, served by the
 * {@code WebSocketHandlerAdapter} every WebFlux configuration declares (Spring Framework 7.0.9
 * {@code WebFluxConfigurationSupport#webFluxWebSocketHandlerAdapter}). Its {@code handle(session)} runs once per
 * session, and Reactor Netty subscribes what it returns with the upgrade request's Reactor Context
 * ({@code HttpServerOperations#withWebsocketSupport}: {@code websocketSubscriber(signal.getContextView())}), which
 * carries the handshake's {@code SecurityContext}: the reactive checks it reaches see the handshake's user.
 */
@Supports(Feature.WEBSOCKET_MESSAGES)
final class WebSocketHandlers {

    static final String WEBSOCKET = "WEBSOCKET";
    private static final String CONFIGURER = "org.springframework.web.socket.config.annotation.WebSocketConfigurer";
    private static final String REGISTRY = "org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry";
    /**
     * {@code registry.addHandler(a, "/a").addHandler(b, "/b")}: the chained one is on the registration.
     */
    private static final String REGISTRATION =
            "org.springframework.web.socket.config.annotation.WebSocketHandlerRegistration";
    private static final String ENABLE = "org.springframework.web.socket.config.annotation.EnableWebSocket";
    private static final String HANDLER = "org.springframework.web.socket.WebSocketHandler";
    private static final List<String> HANDLE = List.of("handleTextMessage", "handleBinaryMessage", "handleMessage");
    private static final String REACTIVE_SOCKET = "org.springframework.web.reactive.socket.";
    private static final String REACTIVE_HANDLER = REACTIVE_SOCKET + "WebSocketHandler";
    private static final String REACTIVE_SESSION = REACTIVE_SOCKET + "WebSocketSession";
    private static final String URL_MAPPING = "org.springframework.web.reactive.handler.SimpleUrlHandlerMapping";
    /**
     * Where a URL map's entries are written: {@code map.put(path, handler)}, {@code Map.of(path, handler, ..)},
     * {@code Map.entry(path, handler)}, Kotlin's {@code path to handler}.
     */
    private static final Set<String> MAPS = Set.of("java.util.Map", "java.util.HashMap", "java.util.LinkedHashMap",
            "java.util.TreeMap", "java.util.concurrent.ConcurrentHashMap");

    private static final String SERVER_ENDPOINT = "jakarta.websocket.server.ServerEndpoint";
    private static final List<String> ON_MESSAGE = List.of("jakarta.websocket.OnMessage", "jakarta.websocket.OnOpen");

    private final ScanContext context;
    private final List<Finding> findings = new ArrayList<>();
    /**
     * Decision 0113: the handshakes each handler's transport stands for, when there are more than it.
     */
    private final java.util.Map<String, List<Ingress>> ways = new java.util.LinkedHashMap<>();

    WebSocketHandlers(ScanContext context) {
        this.context = context;
    }

    static boolean isWebSocket(Ingress ingress) {
        return WEBSOCKET.equals(ingress.httpMethod());
    }

    /**
     * A WebFlux handler, whose session runs with the handshake's Reactor Context, so it has a caller.
     */
    static boolean reactive(Ingress ingress) {
        return isWebSocket(ingress) && ingress.handler().method().contains(REACTIVE_SESSION);
    }

    /**
     * OPAQUE_CONFIG for a WebFlux handler AuthTracer can't follow.
     */
    List<Finding> findings() {
        return findings;
    }

    /**
     * Decision 0113: the requests a handler's session may arrive in, by its transport's id, where there are several:
     * SockJS's transports.
     */
    java.util.Map<String, List<Ingress>> ways() {
        return ways;
    }

    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        if (WebStack.reactive(context)) {
            SpringBeans.beanMethods(context).stream().filter(JavaSootMethod::hasBody)
                    .forEach(method -> urlMapped(method, mappings));
            return mappings;
        }
        serverEndpoints(mappings);
        if (!context.anyClassAnnotated(ENABLE)) {
            return mappings;
        }
        for (JavaSootClass cls : context.applicationClasses()) {
            if (context.interfacesOf(cls.getType()).stream()
                    .noneMatch(type -> type.getFullyQualifiedName().equals(CONFIGURER))) {
                continue;
            }
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    String owner = invoke.map(found -> found.getMethodSignature().getDeclClassType()
                            .getFullyQualifiedName()).orElse("");
                    // Both take (handler, String... paths).
                    if (invoke.isEmpty() || !invoke.get().getMethodSignature().getName().equals("addHandler")
                            || !(owner.equals(REGISTRY) || owner.equals(REGISTRATION))) {
                        continue;
                    }
                    registered(method, stmt, invoke.get(), mappings);
                }
            }
        }
        return mappings;
    }

    /**
     * One {@code addHandler(handler, paths...)}: the handler at each path, behind its handshake, or SockJS's
     * transports. Decision 0113: a handler whose class AuthTracer can't tell keeps its paths, with a finding; paths it
     * can't read are {@code /**}, with a finding (the weaker reading: every handshake rule is met).
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void registered(JavaSootMethod method, Stmt stmt, AbstractInvokeExpr invoke,
            List<RequestMappings.Mapping> mappings) {
        CodeRef at = MethodNames.codeRef(method.getSignature());
        Optional<ClassType> type = handlerClass(method, invoke.getArg(0), HANDLER);
        Optional<JavaSootMethod> handler = type.flatMap(this::handleMethod);
        if (type.isPresent() && handler.isEmpty()) {
            // The application's handler takes no messages, or a library's handler (Spring's per-connection one) runs.
            return;
        }
        List<String> paths = invoke.getArgCount() < 2 ? List.of()
                : Locals.strings(method.getBody(), invoke.getArg(1));
        if (paths.isEmpty()) {
            findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The WebSocketConfigurer "
                    + MethodNames.key(method.getSignature()) + " registers a WebSocketHandler at paths AuthTracer"
                    + " can't read: it is shown as WEBSOCKET /**", at));
            paths = List.of("/**");
        }
        Optional<JavaSootMethod> handles = handler.or(() -> context.findMethod(context.view().getIdentifierFactory()
                .getMethodSignature(context.type(HANDLER), "handleMessage", "void",
                        List.of("org.springframework.web.socket.WebSocketSession",
                                "org.springframework.web.socket.WebSocketMessage"))));
        if (handler.isEmpty()) {
            findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The WebSocketConfigurer "
                    + MethodNames.key(method.getSignature()) + " registers a WebSocketHandler AuthTracer can't tell"
                    + " at " + String.join(", ", paths) + ": what its messages check and call is not in the graph,"
                    + " only its handshake's rules", at));
        }
        if (handles.isEmpty()) {
            return;
        }
        boolean sockJs = sockJs(method, stmt);
        for (String path : paths) {
            String route = RequestMappings.join("", path);
            List<Ingress> handshakes = handshakes(route, sockJs);
            RequestMappings.Mapping mapping = new RequestMappings.Mapping(Ingress.of(WEBSOCKET, route,
                    handler.map(found -> MethodNames.codeRef(found.getSignature())).orElse(at)), handles.get(), true,
                    handshakes.getFirst());
            if (handshakes.size() > 1) {
                ways.put(handshakes.getFirst().id(), handshakes);
            }
            mappings.add(mapping);
        }
    }

    /**
     * Decision 0113: JSR-356 endpoints, {@code @ServerEndpoint("/path")} classes (a {@code ServerEndpointExporter}
     * bean registers them, or the container's scan in a war): their {@code @OnMessage} method (else {@code @OnOpen})
     * behind the handshake, whose request passes the filter chain. Messages arrive on the container's threads, as a
     * plain handler's do.
     */
    private void serverEndpoints(List<RequestMappings.Mapping> mappings) {
        for (JavaSootClass cls : context.applicationClasses()) {
            Optional<sootup.java.core.AnnotationUsage> endpoint = context.findAnnotation(cls, SERVER_ENDPOINT);
            if (endpoint.isEmpty()) {
                continue;
            }
            Optional<JavaSootMethod> handler = ON_MESSAGE.stream().flatMap(annotation -> cls.getMethods().stream()
                    .filter(method -> method.hasBody() && context.hasAnnotation(method, annotation)))
                    .findFirst();
            String path = dev.crain.authtracer.scan.Annotations.string(endpoint.get(), "value").orElse("/");
            if (handler.isEmpty()) {
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The @ServerEndpoint " + cls.getName() + " at "
                        + path + " has no @OnMessage or @OnOpen method AuthTracer can follow: its sessions aren't in"
                        + " the graph", CodeRef.ofClass(cls.getName())));
                continue;
            }
            mappings.add(mapping(RequestMappings.join("", path), handler.get(),
                    MethodNames.codeRef(handler.get().getSignature())));
        }
    }

    private static RequestMappings.Mapping mapping(String route, JavaSootMethod handler, CodeRef ref) {
        return new RequestMappings.Mapping(Ingress.of(WEBSOCKET, route, ref), handler, true,
                Ingress.of("GET", route, null));
    }

    /**
     * Decision 0113: the requests a WebSocket session at the route may arrive in. Without SockJS its handshake,
     * {@code GET /ws}. With it, spring-websocket 7.0.9 maps the endpoint's {@code SockJsHttpRequestHandler} at
     * {@code /ws/**} ({@code WebMvcStompWebSocketEndpointRegistration#getMappings}): the info and iframe pages, the
     * raw {@code /ws/websocket}, and {@code /ws/{server}/{session}/{transport}}, whose transports are {@code GET}
     * ({@code websocket}, {@code eventsource}, {@code htmlfile}) or {@code POST} ({@code xhr}, {@code xhr_send},
     * {@code xhr_streaming}; {@code TransportType}).
     */
    static List<Ingress> handshakes(String route, boolean sockJs) {
        if (!sockJs) {
            return List.of(Ingress.of("GET", route, null));
        }
        String under = RequestMappings.join(route, "/**");
        return List.of(Ingress.of("GET", under, null), Ingress.of("POST", under, null));
    }

    /**
     * Decision 0113: whether the registration the statement makes ({@code registry.addEndpoint(..)},
     * {@code registry.addHandler(..)}) turns SockJS on: {@code withSockJS()} on it, or on what its chained calls
     * return.
     */
    static boolean sockJs(JavaSootMethod method, Stmt registration) {
        if (!(registration instanceof sootup.core.jimple.common.stmt.JAssignStmt assign)
                || !(assign.getLeftOp() instanceof Local result)) {
            return false;
        }
        Set<Local> chain = new java.util.HashSet<>(Set.of(result));
        boolean after = false;
        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt == registration) {
                after = true;
                continue;
            }
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (!after || invoke.isEmpty()
                    || !(invoke.get() instanceof sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr call)
                    || !(call.getBase() instanceof Local base) || !chain.contains(base)) {
                continue;
            }
            if (call.getMethodSignature().getName().equals("withSockJS")) {
                return true;
            }
            if (stmt instanceof sootup.core.jimple.common.stmt.JAssignStmt next
                    && next.getLeftOp() instanceof Local returned) {
                chain.add(returned);
            }
        }
        return false;
    }

    /**
     * A bean method that builds a WebFlux {@code SimpleUrlHandlerMapping} (its constructor or {@code setUrlMap}): each
     * entry of its URL maps whose value is a {@code WebSocketHandler}. A handler AuthTracer can't follow keeps its path,
     * pointing at the bean, with a finding.
     */
    @Supports(Feature.FINDING_OPAQUE_CONFIG)
    private void urlMapped(JavaSootMethod method, List<RequestMappings.Mapping> mappings) {
        boolean maps = method.getBody().getStmts().stream().map(Locals::invoke).flatMap(Optional::stream)
                .anyMatch(invoke -> invoke.getMethodSignature().getDeclClassType().getFullyQualifiedName()
                        .equals(URL_MAPPING) && invoke.getArgCount() > 0
                        && (invoke.getMethodSignature().getName().equals("<init>")
                                || invoke.getMethodSignature().getName().equals("setUrlMap")));
        if (!maps) {
            return;
        }
        for (Stmt stmt : method.getBody().getStmts()) {
            Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
            if (invoke.isEmpty()) {
                continue;
            }
            List<Immediate> pairs = entries(invoke.get());
            for (int i = 0; i + 1 < pairs.size(); i += 2) {
                Value value = pairs.get(i + 1);
                if (!handles(value)) {
                    continue;
                }
                Optional<JavaSootMethod> handler = lambda(method, value)
                        .or(() -> handlerClass(method, value, REACTIVE_HANDLER).flatMap(this::reactiveHandle));
                Value key = pairs.get(i) instanceof Local local ? Locals.definition(method.getBody(), local)
                        .orElse(local) : pairs.get(i);
                CodeRef bean = MethodNames.codeRef(method.getSignature());
                String route = key instanceof StringConstant path ? RequestMappings.join("", path.getValue()) : "/**";
                if (!(key instanceof StringConstant)) {
                    // The weaker reading: any path, so every handshake rule it may meet is considered.
                    findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The HandlerMapping bean "
                            + MethodNames.key(method.getSignature()) + " maps a WebSocketHandler at a path AuthTracer"
                            + " can't read: it is shown as WEBSOCKET /**", bean));
                }
                if (handler.isPresent()) {
                    mappings.add(mapping(route, handler.get(), MethodNames.codeRef(handler.get().getSignature())));
                    continue;
                }
                findings.add(new Finding(Finding.Kind.OPAQUE_CONFIG, "The HandlerMapping bean "
                        + MethodNames.key(method.getSignature()) + " maps " + route + " to a WebSocketHandler"
                        + " AuthTracer can't follow: what its sessions check and call is not in the graph", bean));
                // The interface's method has no body: the path keeps its handshake's rules alone.
                context.findMethod(context.view().getIdentifierFactory().getMethodSignature(
                        context.type(REACTIVE_HANDLER), "handle", "reactor.core.publisher.Mono",
                        List.of(REACTIVE_SESSION))).ifPresent(handle -> mappings.add(mapping(route, handle, bean)));
            }
        }
    }

    /**
     * The key and value arguments of a URL map entry the call writes, in pairs.
     */
    private static List<Immediate> entries(AbstractInvokeExpr invoke) {
        MethodSignature called = invoke.getMethodSignature();
        String owner = called.getDeclClassType().getFullyQualifiedName();
        // put(key, value), of(k1, v1, ..), entry(key, value); Kotlin's to(key, value).
        boolean writes = MAPS.contains(owner) && Set.of("put", "of", "entry").contains(called.getName())
                || owner.equals("kotlin.TuplesKt") && called.getName().equals("to");
        return writes ? invoke.getArgs() : List.of();
    }

    /**
     * Whether a map value is a WebFlux {@code WebSocketHandler}: its local's type (a lambda's is the interface).
     */
    private boolean handles(Value value) {
        return value.getType() instanceof ClassType type
                && SpringBeans.assignable(context, type, Set.of(REACTIVE_HANDLER));
    }

    /**
     * A handler written as a lambda or method reference: its body.
     */
    private Optional<JavaSootMethod> lambda(JavaSootMethod method, Value value) {
        return value instanceof Local local && Locals.definition(method.getBody(), local)
                .orElse(null) instanceof JDynamicInvokeExpr dynamic
                        ? new CallTraversal(context).targets(dynamic).stream().findFirst() : Optional.empty();
    }

    /**
     * The handler's class: what is created there; what the application method that returns it creates, or its
     * return type; the argument's static type; else the application's only handler of that kind.
     */
    private Optional<ClassType> handlerClass(JavaSootMethod method, Value argument, String kind) {
        if (!(argument instanceof Local local)) {
            return Optional.empty();
        }
        Optional<ClassType> created = Locals.created(method.getBody(), local);
        if (created.isPresent()) {
            return created;
        }
        if (Locals.definition(method.getBody(), local).orElse(null) instanceof AbstractInvokeExpr call) {
            // registry.addHandler(chatHandler(), "/chat"), with @Bean WebSocketHandler chatHandler().
            Optional<ClassType> returned = context.isApplication(call.getMethodSignature().getDeclClassType())
                    ? context.findMethod(call.getMethodSignature()).flatMap(WebSocketHandlers::returnsCreated)
                    : Optional.empty();
            if (returned.isEmpty() && call.getMethodSignature().getType() instanceof ClassType type
                    && context.isApplication(type)) {
                returned = Optional.of(type);
            }
            if (returned.isPresent()) {
                return returned;
            }
        }
        if (local.getType() instanceof ClassType type && context.isApplication(type)) {
            return Optional.of(type);
        }
        List<ClassType> implementations = context.subtypesOf(context.type(kind)).stream()
                .filter(context::isApplication).toList();
        return implementations.size() == 1 ? Optional.of(implementations.getFirst()) : Optional.empty();
    }

    /**
     * The class a method creates and returns: {@code return new ChatHandler();}.
     */
    private static Optional<ClassType> returnsCreated(JavaSootMethod method) {
        if (!method.hasBody()) {
            return Optional.empty();
        }
        return method.getBody().getStmts().stream()
                .flatMap(stmt -> stmt instanceof JReturnStmt result && result.getOp() instanceof Local returned
                        ? Locals.created(method.getBody(), returned).stream() : Stream.empty())
                .findFirst();
    }

    /**
     * The method that takes the messages, in the class or an application superclass.
     */
    private Optional<JavaSootMethod> handleMethod(ClassType type) {
        for (String name : HANDLE) {
            Optional<JavaSootMethod> found = own(type, name);
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }

    /**
     * A WebFlux handler's {@code handle(WebSocketSession)}, in the class or an application superclass.
     */
    private Optional<JavaSootMethod> reactiveHandle(ClassType type) {
        return own(type, "handle").filter(method -> method.getParameterCount() == 1);
    }

    private Optional<JavaSootMethod> own(ClassType type, String name) {
        List<ClassType> chain = new ArrayList<>(List.of(type));
        chain.addAll(context.superClassesOf(type));
        for (ClassType candidate : chain) {
            if (!context.isApplication(candidate)) {
                continue;
            }
            Optional<JavaSootMethod> found = context.findClass(candidate).flatMap(cls -> cls.getMethods().stream()
                    .filter(method -> method.getName().equals(name) && method.hasBody()).findFirst());
            if (found.isPresent()) {
                return found;
            }
        }
        return Optional.empty();
    }
}
