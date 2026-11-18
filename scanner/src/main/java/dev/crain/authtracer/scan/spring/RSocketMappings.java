package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.Annotations;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import dev.crain.authtracer.scan.flow.Payloads;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0045 (RX-13): RSocket routes. Spring Boot starts an RSocket server on {@code spring.rsocket.server.port},
 * or on the WebFlux server at {@code spring.rsocket.server.mapping-path} with the {@code websocket} transport; its
 * {@code RSocketMessageHandler} serves the {@code @MessageMapping} methods of {@code @Controller}s, routes joined with
 * {@code .}: an Ingress {@code RSOCKET profile.{name}} answered with what the method returns. Over WebSocket, the
 * handshake ({@code GET <mapping-path>}) passes the HTTP rules first.
 */
@Supports(Feature.RSOCKET_ROUTES)
final class RSocketMappings {

    private static final Logger log = LoggerFactory.getLogger(RSocketMappings.class);

    static final String RSOCKET = "RSOCKET";
    private static final String MESSAGE_HANDLER =
            "org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler";
    private static final String MESSAGE_MAPPING = "org.springframework.messaging.handler.annotation.MessageMapping";

    private final ScanContext context;

    RSocketMappings(ScanContext context) {
        this.context = context;
    }

    static boolean isRSocket(Ingress ingress) {
        return RSOCKET.equals(ingress.httpMethod());
    }

    /**
     * Whether Spring Boot starts an RSocket server: the messaging handler is on the classpath and a port, or a
     * WebSocket mapping path, is configured.
     */
    boolean server() {
        if (context.findClass(MESSAGE_HANDLER).isEmpty()
                || !context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)) {
            return false;
        }
        return portConfigured() || webSocketPath().isPresent();
    }

    /**
     * Whether {@code spring.rsocket.server.port} is set, if only from the environment ({@code ${RSOCKET_PORT}}): Boot
     * 4.1's embedded server is {@code @ConditionalOnProperty("spring.rsocket.server.port")}, on whatever port that
     * resolves to.
     */
    private boolean portConfigured() {
        return context.properties().getResolvingKnown("spring.rsocket.server.port").isPresent();
    }

    /**
     * {@code spring.rsocket.server.mapping-path} with the {@code websocket} transport and no port of its own.
     */
    Optional<String> webSocketPath() {
        return context.properties().get("spring.rsocket.server.mapping-path")
                .filter(path -> context.properties().get("spring.rsocket.server.transport")
                        .filter(transport -> transport.equalsIgnoreCase("websocket")).isPresent()
                        && !portConfigured());
    }

    /**
     * The standalone server's port, which the linker matches calls to.
     */
    @Supports(Feature.SYSTEM_GRAPH)
    Optional<Integer> port() {
        return context.properties().get("spring.rsocket.server.port").flatMap(port -> {
            try {
                return Optional.of(Integer.parseInt(port.trim()));
            }
            catch (NumberFormatException e) {
                log.warn("Scanning {}: spring.rsocket.server.port is '{}', not a port AuthTracer can read, so calls"
                        + " to the RSocket server's port aren't matched to it", context.input().service(), port);
                return Optional.empty();
            }
        });
    }

    List<RequestMappings.Mapping> detect(SpringBeans beans) {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        if (!server()) {
            return mappings;
        }
        Ingress transport = webSocketPath().map(path -> Ingress.of("GET", RequestMappings.join("", path), null))
                .orElse(null);
        for (JavaSootClass cls : context.applicationClasses()) {
            if (!beans.isController(cls)) {
                continue;
            }
            List<String> prefixes = context.findAnnotation(cls, MESSAGE_MAPPING)
                    .map(annotation -> Annotations.strings(annotation, "value")).filter(values -> !values.isEmpty())
                    .orElse(List.of(""));
            for (JavaSootMethod method : cls.getMethods()) {
                if (!context.hasAnnotation(method, MESSAGE_MAPPING)) {
                    continue;
                }
                List<String> routes = context.findAnnotation(method, MESSAGE_MAPPING)
                        .map(annotation -> Annotations.strings(annotation, "value")).filter(values -> !values.isEmpty())
                        .orElse(List.of(""));
                for (String prefix : prefixes) {
                    for (String route : routes) {
                        Ingress ingress = Ingress.of(RSOCKET, join(prefix, route),
                                MethodNames.codeRef(method.getSignature()))
                                .withResponse(Payloads.returnedBy(context, method.getSignature()).orElse(null));
                        mappings.add(new RequestMappings.Mapping(ingress, method, true, transport));
                    }
                }
            }
        }
        return mappings;
    }

    /**
     * {@code RSocketMessageHandler}'s default route matcher separates segments with {@code .}.
     */
    static String join(String prefix, String route) {
        return prefix.isEmpty() ? route : route.isEmpty() ? prefix : prefix + "." + route;
    }
}
