package fixtures.webfluxsocket;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.HandlerMapping;
import org.springframework.web.reactive.handler.SimpleUrlHandlerMapping;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Mono;

/**
 * WebFlux WebSocket handlers, mapped by URL in {@code SimpleUrlHandlerMapping} beans: a bean, an object made there and
 * a lambda. The chat handler reaches a reactive method check, which sees the handshake's user in the Reactor Context.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class SocketConfig {

    @Bean
    HandlerMapping sockets(ChatHandler chat) {
        Map<String, WebSocketHandler> map = new HashMap<>();
        map.put("/chat", chat);
        map.put("/feed", new FeedHandler());
        return new SimpleUrlHandlerMapping(map, -1);
    }

    @Bean
    SimpleUrlHandlerMapping pings() {
        SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping();
        mapping.setUrlMap(Map.of("/ping", (WebSocketHandler) session -> session.send(session.receive()
                .map(message -> session.textMessage("pong")))));
        mapping.setOrder(-1);
        return mapping;
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/feed", "/ping").permitAll()
                .anyExchange().authenticated()).build();
    }
}

@Service
class Moderation {

    @PreAuthorize("hasRole('USER')")
    public Mono<String> check(String text) {
        return Mono.just(text);
    }
}

@Component
class ChatHandler implements WebSocketHandler {

    private final Moderation moderation;

    ChatHandler(Moderation moderation) {
        this.moderation = moderation;
    }

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        return session.send(session.receive().flatMap(message -> moderation.check(message.getPayloadAsText()))
                .map(session::textMessage));
    }
}

class FeedHandler implements WebSocketHandler {

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        return session.send(session.receive().map(message -> session.textMessage("news")));
    }
}

/**
 * A handler typed as the interface, which more than one class implements, and a path from configuration.
 */
@Configuration
class AlertSockets {

    @Bean
    HandlerMapping alerts(@Value("${alerts.path:/alerts/live}") String path, WebSocketHandler alertHandler) {
        return new SimpleUrlHandlerMapping(Map.of("/alerts", alertHandler, path, alertHandler), 1);
    }
}
