package fixtures.websocketforms;

import jakarta.websocket.OnMessage;
import jakarta.websocket.server.ServerEndpoint;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.springframework.web.socket.server.standard.ServerEndpointExporter;

/**
 * Decision 0113: a plain handler with SockJS, one AuthTracer can't follow at a path from configuration, and a JSR-356
 * endpoint.
 */
@Configuration
@EnableWebSocket
@EnableWebSecurity
@EnableMethodSecurity
class WebSocketFormsApp implements WebSocketConfigurer {

    private final WebSocketHandler feed;
    private final String feedPath;

    WebSocketFormsApp(WebSocketHandler feed, @Value("${feed.path:/feed}") String feedPath) {
        this.feed = feed;
        this.feedPath = feedPath;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(new EchoHandler(), "/echo").withSockJS();
        registry.addHandler(feed, feedPath);
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/echo").authenticated()
                .requestMatchers("/tickets").hasRole("SUPPORT")
                .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    static ServerEndpointExporter serverEndpointExporter() {
        return new ServerEndpointExporter();
    }

    @Bean
    WebSocketHandler feed() {
        return new EchoHandler();
    }
}

class EchoHandler extends TextWebSocketHandler {

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        session.sendMessage(message);
    }
}

class QuietHandler extends TextWebSocketHandler {
}

@Service
class Tickets {

    @PreAuthorize("hasRole('SUPPORT')")
    public void open(String text) {
    }
}

@ServerEndpoint("/tickets")
class TicketsEndpoint {

    private final Tickets tickets = new Tickets();

    @OnMessage
    public void onMessage(String text) {
        tickets.open(text);
    }
}
