package fixtures.filterhandshake;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.MappedInterceptor;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * Decision 0070 (amended): a WebSocket handshake is a request: it passes the filters, with its caller, and the
 * {@code MappedInterceptor} beans, but not the {@code InterceptorRegistry}'s, which the WebSocket handler mapping
 * isn't given. Its messages still have no caller.
 */
@SpringBootApplication
@EnableWebSocket
@EnableMethodSecurity
class FilterHandshakeApp implements WebSocketConfigurer, WebMvcConfigurer {

    private final Messages messages;

    FilterHandshakeApp(Messages messages) {
        this.messages = messages;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(new ChatHandler(messages), "/chat");
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RegistryInterceptor());
    }

    @Bean
    MappedInterceptor handshakes() {
        return new MappedInterceptor(null, new HandshakeInterceptor());
    }
}

@Component
class TenantFilter extends OncePerRequestFilter {

    private final Tenants tenants;

    TenantFilter(Tenants tenants) {
        this.tenants = tenants;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        request.setAttribute("tenant", tenants.current());
        chain.doFilter(request, response);
    }
}

@Service
class Tenants {

    @PreAuthorize("hasRole('USER')")
    String current() {
        return "tenant";
    }
}

@Service
class Messages {

    @PreAuthorize("hasRole('CHAT')")
    void post(String text) {
    }
}

class ChatHandler extends TextWebSocketHandler {

    private final Messages messages;

    ChatHandler(Messages messages) {
        this.messages = messages;
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        messages.post(message.getPayload());
    }
}

class HandshakeInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.builder().baseUrl("http://audit:8080").build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        client.post().uri("/handshakes").retrieve().toBodilessEntity();
        return true;
    }
}

class RegistryInterceptor implements HandlerInterceptor {

    private final RestClient client = RestClient.builder().baseUrl("http://audit:8080").build();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        client.post().uri("/requests").retrieve().toBodilessEntity();
        return true;
    }
}
