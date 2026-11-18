package fixtures.stompcontrollers;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.messaging.StompSubProtocolErrorHandler;

/**
 * Decision 0039: STOMP without application destination prefixes, controllers with a class-level
 * {@code @MessageMapping} and {@code @SendTo}, replies to the default topic, and pushes to a user's queue.
 */
@Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic", "/queue");
        registry.setUserDestinationPrefix("/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/stomp").setAllowedOriginPatterns("*").withSockJS();
        registry.setErrorHandler(new StompSubProtocolErrorHandler());
    }
}

record Post(String author, String text) {
}

record LoginEvent(String user, String address) {
}

record Notification(String text, String link) {
}

@Controller
@MessageMapping("/rooms")
class RoomController {

    /**
     * Replies to the default destination: /topic, then the message's.
     */
    @MessageMapping("/{room}/send")
    @SendTo
    Post send(Post post) {
        return post;
    }

    @MessageMapping
    @SendToUser("/queue/rooms")
    List<String> list() {
        return List.of("general");
    }
}

/**
 * The class names the destination; the method's @SendTo names none, so the class's is used.
 */
@Controller
@SendTo("/topic/audit")
class AuditController {

    @MessageMapping("/audit/login")
    @SendTo
    LoginEvent login(LoginEvent event) {
        return event;
    }
}

interface Notifier {

    void notify(String user, Notification notification);
}

@Service
class StompNotifier implements Notifier {

    private final SimpMessagingTemplate messaging;

    StompNotifier(SimpMessagingTemplate messaging) {
        this.messaging = messaging;
    }

    @Override
    public void notify(String user, Notification notification) {
        messaging.convertAndSendToUser(user, "/queue/notifications", notification);
        // Again, and to a destination computed for the user: one push, and one AuthTracer can't name.
        messaging.convertAndSendToUser(user, "/queue/notifications", notification);
        messaging.convertAndSend("/topic/notifications/" + user, notification);
        messaging.send("/topic/raw", MessageBuilder.withPayload(new byte[0]).build());
    }
}
