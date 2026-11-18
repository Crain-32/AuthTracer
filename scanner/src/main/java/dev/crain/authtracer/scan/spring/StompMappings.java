package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.Locals;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.GenericTypes;
import dev.crain.authtracer.scan.flow.Payloads;
import sootup.core.jimple.common.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0039: STOMP over WebSocket. A {@code @MessageMapping} method of a {@code @Controller} handles the
 * {@code MESSAGE}s sent to its destination ({@code MESSAGE /app/chat}: the application destination prefix and the
 * mapping), a {@code @SubscribeMapping} method the {@code SUBSCRIBE}s, and both arrive through a STOMP endpoint's
 * WebSocket handshake ({@code GET /ws}), which the HTTP rules check first. A subscription's handler answers the
 * subscriber; a message handler's return value goes to {@code @SendToUser}'s sender or, by default and with
 * {@code @SendTo}, to everyone subscribed to the reply destination ({@code /topic/chat}): a separate Ingress,
 * {@code SUBSCRIBE /topic/chat}, whose callers are the subscribers.
 */
@Supports(Feature.WEBSOCKET_MESSAGES)
final class StompMappings {

    static final String MESSAGE = "MESSAGE";
    static final String SUBSCRIBE = "SUBSCRIBE";
    private static final Set<String> TYPES = Set.of(MESSAGE, SUBSCRIBE);
    private static final String CONFIGURER =
            "org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer";
    private static final String BROKER_REGISTRY = "org.springframework.messaging.simp.config.MessageBrokerRegistry";
    private static final String ENDPOINT_REGISTRY =
            "org.springframework.web.socket.config.annotation.StompEndpointRegistry";
    private static final String MESSAGE_MAPPING = "org.springframework.messaging.handler.annotation.MessageMapping";
    private static final String SUBSCRIBE_MAPPING =
            "org.springframework.messaging.simp.annotation.SubscribeMapping";
    private static final String SEND_TO = "org.springframework.messaging.handler.annotation.SendTo";
    private static final String SEND_TO_USER = "org.springframework.messaging.simp.annotation.SendToUser";

    /**
     * What everyone subscribed to a destination receives: a message handler's reply, or a payload the code sends
     * with {@code SimpMessagingTemplate.convertAndSend(destination, payload)}.
     *
     * @param subscribe {@code SUBSCRIBE <destination>}, answered with the reply or payload
     * @param payload the value sent, {@code null} for the handler's return value
     */
    record Broadcast(Ingress subscribe, JavaSootMethod handler, Ingress transport, Value payload) {
    }

    private static final Set<String> SENDING = Set.of("org.springframework.messaging.simp.SimpMessagingTemplate",
            "org.springframework.messaging.simp.SimpMessageSendingOperations",
            "org.springframework.messaging.core.MessageSendingOperations",
            "org.springframework.messaging.core.AbstractMessageSendingTemplate");

    /**
     * @param prefixes the application destination prefixes, {@code ""} when none is set
     * @param endpoints the STOMP endpoints' paths, each with whether SockJS serves it
     */
    private record Broker(List<String> prefixes, List<Endpoint> endpoints) {
    }

    private record Endpoint(String path, boolean sockJs) {
    }

    private final ScanContext context;
    private final GenericTypes types;
    private final List<Broadcast> broadcasts = new ArrayList<>();
    private final List<Ingress> handshakes = new ArrayList<>();
    private final Optional<SecurityXml.StompBroker> xml;

    /**
     * @param xml decision 0097: the WebSocket namespace's {@code <websocket:message-broker>}, if the XML has one
     */
    StompMappings(ScanContext context, GenericTypes types, Optional<SecurityXml.StompBroker> xml) {
        this.context = context;
        this.types = types;
        this.xml = xml;
    }

    static boolean isMessage(Ingress ingress) {
        return TYPES.contains(ingress.httpMethod());
    }

    /**
     * The handlers of messages and subscriptions, each with its handshake as the transport.
     */
    List<RequestMappings.Mapping> detect(SpringBeans beans) {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        Optional<Broker> broker = broker();
        if (broker.isEmpty()) {
            return mappings;
        }
        // Decision 0113: every endpoint's handshake, and SockJS's transports, reach every handler.
        for (Endpoint endpoint : broker.get().endpoints()) {
            handshakes.addAll(WebSocketHandlers.handshakes(RequestMappings.join("", endpoint.path()),
                    endpoint.sockJs()));
        }
        Ingress transport = handshakes.isEmpty() ? null : handshakes.getFirst();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!beans.isController(cls)) {
                continue;
            }
            List<String> classPaths = context.findAnnotation(cls, MESSAGE_MAPPING)
                    .map(annotation -> Annotations.strings(annotation, "value")).filter(values -> !values.isEmpty())
                    .orElse(List.of(""));
            for (JavaSootMethod method : cls.getMethods()) {
                if (RequestMappings.suspendImpl(method)) {
                    continue;
                }
                boolean message = context.hasAnnotation(method, MESSAGE_MAPPING);
                boolean subscribe = context.hasAnnotation(method, SUBSCRIBE_MAPPING);
                if (!message && !subscribe) {
                    continue;
                }
                List<String> paths = context.findAnnotation(method, subscribe ? SUBSCRIBE_MAPPING : MESSAGE_MAPPING)
                        .map(annotation -> Annotations.strings(annotation, "value")).orElse(List.of());
                Optional<Payload> reply = Payloads.returnedBy(context, method.getSignature());
                Replies replies = replies(cls, method);
                boolean toSender = subscribe || replies.toUser() != null;
                for (String prefix : broker.get().prefixes()) {
                    for (String classPath : classPaths) {
                        for (String path : paths.isEmpty() ? List.of("") : paths) {
                            String lookup = RequestMappings.join(classPath, path);
                            Ingress ingress = Ingress.of(subscribe ? SUBSCRIBE : MESSAGE,
                                    RequestMappings.join(prefix, lookup), MethodNames.codeRef(method.getSignature()))
                                    .withResponse(toSender ? reply.orElse(null) : null);
                            // Response set here: the sender gets the reply only from @SendToUser or a subscription.
                            mappings.add(new RequestMappings.Mapping(ingress, method, true, transport));
                            if (!toSender && reply.isPresent()) {
                                List<String> sendTo = Optional.ofNullable(replies.to())
                                        .map(annotation -> Annotations.strings(annotation, "value"))
                                        .filter(values -> !values.isEmpty())
                                        .orElse(List.of(RequestMappings.join("/topic", lookup)));
                                sendTo.forEach(destination -> broadcasts.add(new Broadcast(Ingress.of(SUBSCRIBE,
                                        destination, ingress.handler()).withResponse(reply.get()), method,
                                        transport, null)));
                            }
                        }
                    }
                }
            }
        }
        pushes(transport);
        return mappings;
    }

    /**
     * {@code convertAndSend("/topic/x", payload)} and {@code convertAndSendToUser(user, "/queue/x", payload)} with a
     * constant destination, from any application code.
     */
    private void pushes(Ingress transport) {
        // Each sender of a payload type to a destination once; another type sent there exposes its own fields.
        Set<String> seen = new java.util.HashSet<>();
        broadcasts.forEach(broadcast -> seen.add(sent(broadcast.subscribe(), broadcast.handler())));
        for (JavaSootClass cls : context.applicationClasses()) {
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isEmpty() || !SENDING.contains(invoke.get().getMethodSignature().getDeclClassType()
                            .getFullyQualifiedName())) {
                        continue;
                    }
                    String name = invoke.get().getMethodSignature().getName();
                    int destination = name.equals("convertAndSend") ? 0 : name.equals("convertAndSendToUser") ? 1 : -1;
                    if (destination < 0 || invoke.get().getArgCount() < destination + 2
                            || !(invoke.get().getArg(destination) instanceof StringConstant sent)) {
                        continue;
                    }
                    Value payload = invoke.get().getArg(destination + 1);
                    Optional<Payload> type = types.of(method, payload).flatMap(found -> Payloads.unwrap(context, found, false));
                    String route = destination == 1 ? RequestMappings.join("/user", sent.getValue()) : sent.getValue();
                    Ingress subscribe = Ingress.of(SUBSCRIBE, route, MethodNames.codeRef(method.getSignature(), stmt));
                    if (type.isPresent() && seen.add(sent(subscribe.withResponse(type.get()), method))) {
                        broadcasts.add(new Broadcast(subscribe.withResponse(type.get()), method, transport, payload));
                    }
                }
            }
        }
    }

    /**
     * A handler's {@code @SendToUser} and {@code @SendTo}, as spring-messaging 7.0.9's
     * {@code SendToMethodReturnValueHandler} picks them: the method's when one of them names a destination, else the
     * class's when one of those does, else the method's, else the class's.
     */
    private record Replies(AnnotationUsage toUser, AnnotationUsage to) {

        boolean named() {
            return toUser != null && !Annotations.strings(toUser, "value").isEmpty()
                    || to != null && !Annotations.strings(to, "value").isEmpty();
        }

        boolean any() {
            return toUser != null || to != null;
        }
    }

    private Replies replies(JavaSootClass cls, JavaSootMethod method) {
        Replies own = new Replies(context.findAnnotation(method, SEND_TO_USER).orElse(null),
                context.findAnnotation(method, SEND_TO).orElse(null));
        Replies declared = new Replies(context.findAnnotation(cls, SEND_TO_USER).orElse(null),
                context.findAnnotation(cls, SEND_TO).orElse(null));
        return own.named() ? own : declared.named() ? declared : own.any() ? own : declared;
    }

    private static String sent(Ingress subscribe, JavaSootMethod sender) {
        return subscribe.id() + " " + MethodNames.key(sender.getSignature()) + " " + subscribe.response().type();
    }

    List<Broadcast> broadcasts() {
        return broadcasts;
    }

    /**
     * Decision 0113: the requests a STOMP session may arrive in: each endpoint's handshake ({@code GET /ws}), or with
     * SockJS its transports under the endpoint ({@code GET} and {@code POST /ws/**}). The first is the mappings'
     * transport.
     */
    List<Ingress> handshakes() {
        return handshakes;
    }

    /**
     * The {@code WebSocketMessageBrokerConfigurer}'s application destination prefixes and STOMP endpoints; decision
     * 0097: or the XML's {@code <websocket:message-broker application-destination-prefix>} and
     * {@code <websocket:stomp-endpoint path>}s (Spring 7.0.9 {@code MessageBrokerBeanDefinitionParser}: both lists
     * comma-separated).
     */
    private Optional<Broker> broker() {
        List<String> prefixes = new ArrayList<>(xml.map(SecurityXml.StompBroker::prefixes).orElse(List.of()));
        List<Endpoint> endpoints = new ArrayList<>(xml.map(SecurityXml.StompBroker::endpoints).orElse(List.of())
                .stream().map(path -> new Endpoint(path, false)).toList());
        boolean found = xml.isPresent();
        for (JavaSootClass cls : context.applicationClasses()) {
            if (context.interfacesOf(cls.getType()).stream().noneMatch(type -> type.getFullyQualifiedName()
                    .equals(CONFIGURER))) {
                continue;
            }
            found = true;
            for (JavaSootMethod method : cls.getMethods()) {
                if (!method.hasBody()) {
                    continue;
                }
                for (Stmt stmt : method.getBody().getStmts()) {
                    Optional<AbstractInvokeExpr> invoke = Locals.invoke(stmt);
                    if (invoke.isEmpty() || invoke.get().getArgCount() != 1) {
                        continue;
                    }
                    String owner = invoke.get().getMethodSignature().getDeclClassType().getFullyQualifiedName();
                    String name = invoke.get().getMethodSignature().getName();
                    if (owner.equals(BROKER_REGISTRY) && name.equals("setApplicationDestinationPrefixes")) {
                        prefixes.addAll(strings(method, invoke.get()));
                    }
                    else if (owner.equals(ENDPOINT_REGISTRY) && name.equals("addEndpoint")) {
                        boolean sockJs = WebSocketHandlers.sockJs(method, stmt);
                        strings(method, invoke.get()).forEach(path -> endpoints.add(new Endpoint(path, sockJs)));
                    }
                }
            }
        }
        if (!found) {
            return Optional.empty();
        }
        return Optional.of(new Broker(prefixes.isEmpty() ? List.of("") : prefixes, endpoints));
    }

    /**
     * A varargs call's string constants.
     */
    private static List<String> strings(JavaSootMethod method, AbstractInvokeExpr invoke) {
        return Locals.strings(method.getBody(), invoke.getArg(0));
    }
}
