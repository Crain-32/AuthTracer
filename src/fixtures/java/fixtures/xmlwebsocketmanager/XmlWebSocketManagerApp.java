package fixtures.xmlwebsocketmanager;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.stereotype.Controller;

/**
 * STOMP configured in XML, whose {@code <websocket-message-broker authorization-manager-ref>} names the manager bean
 * built here. No {@code @EnableWebSocketSecurity}: the XML hands the bean to the channel.
 */
@Configuration
class XmlWebSocketManagerConfig {

    @Bean
    AuthorizationManager<Message<?>> messageManager() {
        return MessageMatcherDelegatingAuthorizationManager.builder()
                .simpDestMatchers("/app/orders/**").hasRole("BUYER")
                .simpDestMatchers("/api/**").denyAll()
                .anyMessage().authenticated()
                .build();
    }
}

@Controller
class XmlWebSocketManagerController {

    @MessageMapping("/orders/place")
    void place(String order) {
    }

    @MessageMapping("/status")
    void status(String probe) {
    }
}
