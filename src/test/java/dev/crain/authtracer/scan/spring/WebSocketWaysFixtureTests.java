package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0113: every way a WebSocket session arrives in: each STOMP endpoint, SockJS's transports under an endpoint,
 * a handler AuthTracer can't follow, a JSR-356 endpoint.
 */
class WebSocketWaysFixtureTests {

    private final ApplicationGraph stomp = FixtureScans.scan("stompsockjs");
    private final ApplicationGraph forms = FixtureScans.scan("websocketforms");

    @Test
    void aStompMessageArrivesThroughAnyEndpointAndAnySockJsTransport() {
        // Each way's rule on its way only, then a Split asking for any way's.
        String split = FixtureScans.path(stomp, "ingress:MESSAGE /app/chat").stream()
                .filter(id -> id.startsWith("location:SPLIT:handshakes:")).findFirst().orElseThrow();
        AuthorizationLocation handshake = (AuthorizationLocation) stomp.node(split).orElseThrow();
        assertThat(handshake.requirement().operands()).extracting(Requirement::authorities)
                .flatExtracting(authorities -> authorities).containsExactlyInAnyOrder("ROLE_SOCKJS", "ROLE_CHAT");
    }

    @Test
    void aSockJsHandlerIsReachedUnderItsPath() {
        // /echo is guarded, its SockJS transports under /echo/** aren't.
        assertThat(rule(forms, "WEBSOCKET /echo").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }

    @Test
    void aHandlerAuthTracerCantFollowAtAPathItCantReadIsShownWithFindings() {
        assertThat(forms.node("ingress:WEBSOCKET /**")).isPresent();
        assertThat(forms.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("registers a WebSocketHandler at paths AuthTracer"
                        + " can't read: it is shown as WEBSOCKET /**"))
                .anySatisfy(message -> assertThat(message).contains("registers a WebSocketHandler AuthTracer can't"
                        + " tell at /**"));
    }

    @Test
    void aServerEndpointIsAWayInBehindItsHandshake() {
        Ingress tickets = (Ingress) forms.node("ingress:WEBSOCKET /tickets").orElseThrow();
        assertThat(tickets.handler().key()).startsWith("fixtures.websocketforms.TicketsEndpoint#onMessage(");
        assertThat(rule(forms, "WEBSOCKET /tickets").requirement().authorities()).containsExactly("ROLE_SUPPORT");
    }

    @Test
    void sockJsHandshakes() {
        assertThat(WebSocketHandlers.handshakes("/ws", true)).extracting(Ingress::id)
                .containsExactly("ingress:GET /ws/**", "ingress:POST /ws/**");
        assertThat(WebSocketHandlers.handshakes("/ws", false)).extracting(Ingress::id)
                .containsExactly("ingress:GET /ws");
    }
}
