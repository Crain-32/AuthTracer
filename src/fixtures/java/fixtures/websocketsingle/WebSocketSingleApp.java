package fixtures.websocketsingle;

import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * Decision 0050: a handler injected as a WebSocketHandler: the application's only one.
 */
@Configuration
@EnableWebSocket
class WebSocketSingleConfig implements WebSocketConfigurer {

    private final WebSocketHandler notifications;

    WebSocketSingleConfig(WebSocketHandler notifications) {
        this.notifications = notifications;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(notifications, "/notifications");
    }
}

@Component
class NotificationsHandler extends TextWebSocketHandler {

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
    }
}
