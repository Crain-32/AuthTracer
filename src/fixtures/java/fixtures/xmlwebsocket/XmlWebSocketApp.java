package fixtures.xmlwebsocket;

import java.util.List;

import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.annotation.SubscribeMapping;
import org.springframework.stereotype.Controller;

/**
 * STOMP over WebSocket configured in XML only: WEB-INF/spring/websocket.xml's broker and security.xml's
 * {@code <websocket-message-broker>} rules.
 */
@Controller
class XmlWebSocketController {

    @MessageMapping("/admin/purge")
    @SendTo("/topic/audit/events")
    String purge(String reason) {
        return reason;
    }

    @MessageMapping("/chat/send")
    void send(String text) {
    }

    @MessageMapping("/misc/echo")
    String echo(String text) {
        return text;
    }

    @SubscribeMapping("/rooms")
    List<String> rooms() {
        return List.of("lobby");
    }
}
