package fixtures.xmlwebsocketbeans;

import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * STOMP configured in Java, its security in XML: the XML's manager beans, and a broker with an id the Java
 * configuration hands the inbound channel by injection.
 */
@Configuration
@EnableWebSocketMessageBroker
class XmlWebSocketBeansConfig implements WebSocketMessageBrokerConfigurer {

    private final ChannelInterceptor manualSecurity;

    XmlWebSocketBeansConfig(@Qualifier("manualSecurity") ChannelInterceptor manualSecurity) {
        this.manualSecurity = manualSecurity;
    }

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic");
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws");
    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(manualSecurity);
    }
}

/**
 * The operators' messages.
 */
class OpsMessageManager implements AuthorizationManager<Message<?>> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication, Message<?> message) {
        return AuthorityAuthorizationManager.<Message<?>>hasRole("OPS").authorize(authentication, message);
    }
}

@Controller
class XmlWebSocketBeansController {

    @MessageMapping("/restart")
    void restart(String service) {
    }
}
