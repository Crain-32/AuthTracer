package fixtures.stomp;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.messaging.simp.annotation.SubscribeMapping;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * STOMP over WebSocket: the handshake's HTTP rule, then message rules on the destinations.
 */
@Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic", "/queue");
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws");
    }
}

@Configuration
@EnableWebSecurity
@EnableWebSocketSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/ws").authenticated()
                .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(
            MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        messages.nullDestMatcher().authenticated()
                .simpDestMatchers("/app/admin/**").hasRole("ADMIN")
                .simpSubscribeDestMatchers("/topic/announcements").permitAll()
                .simpDestMatchers("/app/**").hasRole("USER")
                .simpSubscribeDestMatchers("/topic/**", "/user/**").hasRole("USER")
                .anyMessage().denyAll();
        return messages.build();
    }

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
    }
}

record ChatMessage(String from, String text) {
}

record Announcement(String text, String author) {
}

record Order(Long id, String customerEmail, long total) {
}

@RestController
class OrderController {

    private final SimpMessagingTemplate messaging;

    OrderController(SimpMessagingTemplate messaging) {
        this.messaging = messaging;
    }

    @PostMapping("/orders")
    void place(@RequestBody Order order) {
        messaging.convertAndSend("/topic/orders", order);
    }
}

@Controller
class ChatController {

    @MessageMapping("/chat")
    @SendTo("/topic/messages")
    ChatMessage send(ChatMessage message) {
        return message;
    }

    @MessageMapping("/admin/announce")
    @SendTo("/topic/announcements")
    Announcement announce(Announcement announcement) {
        return announcement;
    }

    @MessageMapping("/private")
    @SendToUser("/queue/reply")
    ChatMessage reply(ChatMessage message) {
        return message;
    }

    @SubscribeMapping("/rooms")
    List<String> rooms() {
        return List.of("general");
    }
}
