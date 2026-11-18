package fixtures.stomplambda;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * The application's own message manager, a lambda: it decides every message, and AuthTracer can't read how.
 */
@Configuration
@EnableWebSocketMessageBroker
@EnableWebSocketSecurity
class StompLambdaConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic");
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws");
    }

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager() {
        return (authentication, message) -> new AuthorizationDecision(
                SimpMessageHeaderAccessor.getSessionId(message.getHeaders()) != null);
    }
}

@Controller
class TickerController {

    @MessageMapping("/ticker")
    void tick(String symbol) {
    }
}
