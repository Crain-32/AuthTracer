package fixtures.stomptopics;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.messaging.simp.annotation.SendToUser;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * Message rules on message types and on a destination that isn't a constant, and two handlers that send to one
 * topic.
 */
@Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic");
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
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/ws").permitAll()
                .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(
            MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        messages.simpTypeMatchers(SimpMessageType.SUBSCRIBE).hasRole("SUBSCRIBER")
                .simpDestMatchers(openPrefix() + "/**").permitAll()
                .anyMessage().hasRole("USER");
        return messages.build();
    }

    static String openPrefix() {
        return System.getProperty("open.prefix", "/app/open");
    }
}

record News(String headline) {
}

record Alert(String level, String detail) {
}

@Controller
class NewsController {

    @MessageMapping("/news")
    @SendTo("/topic/public")
    News news(News news) {
        return news;
    }

    @MessageMapping("/alert")
    @SendTo("/topic/public")
    Alert alert(Alert alert) {
        return alert;
    }
}

record Bulletin(String secretDetail) {
}

/**
 * Pushes a third type to the topic the handlers send to.
 */
@Service
class Bulletins {

    private final SimpMessagingTemplate template;

    Bulletins(SimpMessagingTemplate template) {
        this.template = template;
    }

    void publish(String detail) {
        template.convertAndSend("/topic/public", new Bulletin(detail));
    }
}

record Balance(long cents) {
}

/**
 * Every handler replies to its sender only.
 */
@Controller
@SendToUser
class BalanceController {

    @MessageMapping("/balance")
    Balance balance() {
        return new Balance(0);
    }
}
