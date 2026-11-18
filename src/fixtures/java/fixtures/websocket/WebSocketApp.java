package fixtures.websocket;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * Decision 0050: plain WebSocket handlers behind their handshakes. The chat handler reaches a method check, which has
 * no SecurityContext on the message's thread.
 */
@Configuration
@EnableWebSocket
@EnableWebSecurity
@EnableMethodSecurity
class WebSocketApp implements WebSocketConfigurer {

    private final ChatHandler chat;

    WebSocketApp(ChatHandler chat) {
        this.chat = chat;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(chat, "/chat").setAllowedOrigins("*").addHandler(new EchoHandler(), "/echo3");
        registry.addHandler(new EchoHandler(), "/echo", "/echo2");
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/echo", "/echo2").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}

@Service
class Moderation {

    @PreAuthorize("hasRole('USER')")
    public void check(String text) {
    }
}

@Component
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

class EchoHandler extends TextWebSocketHandler {

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        session.sendMessage(message);
    }
}
