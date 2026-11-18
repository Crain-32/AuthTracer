package fixtures.stompsockjs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * Decision 0113: two STOMP endpoints, one with SockJS. The rules guard the endpoints' own paths: SockJS's transports
 * under /ws/** and the second endpoint get other rules, and every message handler is reached through any of them.
 */
@Configuration
@EnableWebSocketMessageBroker
class StompSockJsConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic");
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws").setAllowedOriginPatterns("*").withSockJS();
        registry.addEndpoint("/ws-native");
    }
}

@Configuration
@EnableWebSecurity
class StompSockJsSecurity {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/ws").authenticated()
                .requestMatchers("/ws-native").hasRole("CHAT")
                .requestMatchers("/ws/**").hasRole("SOCKJS")
                .anyRequest().denyAll());
        return http.build();
    }
}

@Controller
class ChatController {

    @MessageMapping("/chat")
    void chat(String text) {
    }
}
