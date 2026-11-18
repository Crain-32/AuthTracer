package fixtures.websocketbeans;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.BinaryWebSocketHandler;
import org.springframework.web.socket.handler.PerConnectionWebSocketHandler;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * Decision 0050: handlers registered the way Spring's reference documentation shows, through their @Bean methods
 * (declared as WebSocketHandler, or as the application's type from a factory), a binary handler, and one Spring
 * creates per connection.
 */
@Configuration
@EnableWebSocket
@EnableWebSecurity
@EnableMethodSecurity
class WebSocketBeansConfig implements WebSocketConfigurer {

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(chatHandler(), "/chat").withSockJS();
        registry.addHandler(uploadHandler(), "/uploads");
        registry.addHandler(tickerHandler(), "/ticker");
        registry.addHandler(new PerConnectionWebSocketHandler(PushHandler.class), "/push");
    }

    @Bean
    WebSocketHandler chatHandler() {
        return new ChatHandler(new Moderation());
    }

    @Bean
    WebSocketHandler uploadHandler() {
        return new UploadHandler();
    }

    @Bean
    TickerHandler tickerHandler() {
        return TickerHandler.every(5);
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }
}

@Service
class Moderation {

    @PreAuthorize("hasRole('USER')")
    public void check(String text) {
    }
}

class ChatHandler extends TextWebSocketHandler {

    private final Moderation moderation;

    ChatHandler(Moderation moderation) {
        this.moderation = moderation;
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        moderation.check(message.getPayload());
    }
}

class UploadHandler extends BinaryWebSocketHandler {

    @Override
    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) {
    }
}

class TickerHandler extends TextWebSocketHandler {

    private final int seconds;

    private TickerHandler(int seconds) {
        this.seconds = seconds;
    }

    static TickerHandler every(int seconds) {
        return new TickerHandler(seconds);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
    }
}

/**
 * Only pushes: it takes no messages.
 */
class PushHandler extends TextWebSocketHandler {

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
    }
}
