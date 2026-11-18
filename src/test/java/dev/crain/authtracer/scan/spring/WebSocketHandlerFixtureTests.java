package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0050: plain WebSocket handlers.
 */
class WebSocketHandlerFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("websocket");

    @Test
    void handlersAreIngressBehindTheirHandshakes() {
        assertThat(graph.nodes(Ingress.class)).filteredOn(WebSocketHandlers::isWebSocket).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:WEBSOCKET /chat", "ingress:WEBSOCKET /echo",
                        "ingress:WEBSOCKET /echo2", "ingress:WEBSOCKET /echo3");
        assertThat(((Ingress) graph.node("ingress:WEBSOCKET /chat").orElseThrow()).handler().className())
                .isEqualTo("fixtures.websocket.ChatHandler");
        assertThat(checks("ingress:WEBSOCKET /echo")).singleElement().satisfies(handshake -> {
            assertThat(handshake.mechanism()).isEqualTo("authorizeHttpRequests");
            assertThat(handshake.requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        });
    }

    @Test
    void aMessagesMethodChecksHaveNoSecurityContext() {
        List<AuthorizationLocation> chat = checks("ingress:WEBSOCKET /chat");
        assertThat(chat).extracting(AuthorizationLocation::mechanism)
                .containsExactly("authorizeHttpRequests", "@PreAuthorize (no caller)");
        assertThat(chat.getFirst().requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .singleElement().satisfies(finding -> assertThat(finding.message())
                        .contains("WEBSOCKET /chat takes a message", "Moderation#check"));
    }

    @Test
    void handlersRegisteredThroughTheirBeanMethods() {
        ApplicationGraph beans = FixtureScans.scan("websocketbeans");
        // A @Bean declared as WebSocketHandler is the handler it creates; one from a factory is its declared type;
        // a binary handler takes binary messages. The per-connection handler is Spring's, and its PushHandler takes
        // no messages.
        assertThat(beans.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:WEBSOCKET /chat", "ingress:WEBSOCKET /uploads", "ingress:WEBSOCKET /ticker");
        assertThat(((Ingress) beans.node("ingress:WEBSOCKET /uploads").orElseThrow()).handler().method())
                .startsWith("handleBinaryMessage(");
        assertThat(path(beans, "ingress:WEBSOCKET /chat"))
                .contains("location:METHOD:fixtures.websocketbeans.Moderation#check(java.lang.String):@PreAuthorize"
                        + ":no-caller");
        // A handler injected as a WebSocketHandler is the application's only one.
        assertThat(((Ingress) FixtureScans.scan("websocketsingle").node("ingress:WEBSOCKET /notifications")
                .orElseThrow()).handler().className()).isEqualTo("fixtures.websocketsingle.NotificationsHandler");
    }

    @Test
    void webFluxHandlersMappedByUrlAreIngressBehindTheirHandshakes() {
        ApplicationGraph webFlux = FixtureScans.scan("webfluxsocket");
        assertThat(webFlux.nodes(Ingress.class)).filteredOn(WebSocketHandlers::isWebSocket).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:WEBSOCKET /chat", "ingress:WEBSOCKET /feed",
                        "ingress:WEBSOCKET /ping", "ingress:WEBSOCKET /alerts", "ingress:WEBSOCKET /**");
        assertThat(((Ingress) webFlux.node("ingress:WEBSOCKET /feed").orElseThrow()).handler())
                .satisfies(handler -> {
                    assertThat(handler.className()).isEqualTo("fixtures.webfluxsocket.FeedHandler");
                    assertThat(handler.method()).startsWith("handle(");
                });
        // A lambda handler is its body.
        assertThat(((Ingress) webFlux.node("ingress:WEBSOCKET /ping").orElseThrow()).handler().method())
                .startsWith("lambda$pings$");
        assertThat(checks(webFlux, "ingress:WEBSOCKET /ping")).singleElement().satisfies(handshake -> {
            assertThat(handshake.mechanism()).isEqualTo("authorizeExchange");
            assertThat(handshake.requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        });
        // Kotlin's mapOf(path to handler).
        assertThat(((Ingress) FixtureScans.scan("webfluxsocketkotlin").node("ingress:WEBSOCKET /quotes")
                .orElseThrow()).handler().className()).isEqualTo("fixtures.webfluxsocketkotlin.QuotesHandler");
    }

    @Test
    void aWebFluxSessionsReactiveChecksSeeTheHandshakesUser() {
        // Reactor Netty subscribes the handler with the upgrade's Reactor Context, which carries the SecurityContext.
        ApplicationGraph webFlux = FixtureScans.scan("webfluxsocket");
        assertThat(checks(webFlux, "ingress:WEBSOCKET /chat")).extracting(AuthorizationLocation::mechanism)
                .containsExactly("authorizeExchange", "@PreAuthorize");
        assertThat(webFlux.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED);
    }

    @Test
    void aWebFluxHandlerOrPathItCantReadKeepsTheEndpointWithAFinding() {
        ApplicationGraph webFlux = FixtureScans.scan("webfluxsocket");
        // Typed as the interface, which two classes implement: the Ingress points at the bean, behind its handshake.
        assertThat(((Ingress) webFlux.node("ingress:WEBSOCKET /alerts").orElseThrow()).handler().method())
                .startsWith("alerts(");
        assertThat(checks(webFlux, "ingress:WEBSOCKET /alerts")).extracting(AuthorizationLocation::mechanism)
                .containsExactly("authorizeExchange");
        assertThat(webFlux.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("maps /alerts to a WebSocketHandler AuthTracer can't follow"))
                .anySatisfy(message -> assertThat(message).contains("at a path AuthTracer can't read: it is shown"
                        + " as WEBSOCKET /**"));
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return checks(graph, ingress);
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
