package fixtures.stompmanual;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.messaging.access.expression.MessageExpressionAuthorizationManager;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * MSG-05: the application adds Spring Security's channel interceptor itself, with an expression rule (MSG-04).
 */
@Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws");
    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        AuthorizationManager<Message<?>> manager = MessageMatcherDelegatingAuthorizationManager.builder()
                .simpDestMatchers("/app/admin/**").access(new MessageExpressionAuthorizationManager("hasRole('ADMIN')"))
                .anyMessage().hasRole("USER")
                .build();
        registration.interceptors(new SecurityContextChannelInterceptor(),
                new AuthorizationChannelInterceptor(manager));
    }
}

@Controller
class AdminController {

    @MessageMapping("/admin/reset")
    void reset() {
    }

    @MessageMapping("/ping")
    void ping() {
    }
}
