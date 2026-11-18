package fixtures.stomprules;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.socket.EnableWebSocketSecurity;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * Each of the message rule builder's matchers and requirements, Spring Security's managers given to
 * {@code access(..)}, a {@code MessageMatcher} AuthTracer can't evaluate, and no {@code anyMessage()} at the end.
 */
@Configuration
@EnableWebSocketMessageBroker
class StompRulesConfig implements WebSocketMessageBrokerConfigurer {

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
class StompRulesSecurity {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(
            MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        messages.simpMessageDestMatchers("/app/admin/**").hasAuthority("SCOPE_admin")
                .simpSubscribeDestMatchers("/topic/audit/**").fullyAuthenticated()
                .simpDestMatchers("/app/saved/**").rememberMe()
                .simpDestMatchers("/app/guest/**").anonymous()
                .simpDestMatchers("/app/reports/**")
                .access(AuthorityAuthorizationManager.hasAnyAuthority("SCOPE_reports", "SCOPE_admin"))
                .simpDestMatchers("/app/groups/**")
                .access(AuthorityAuthorizationManager.hasAnyRole("GROUP_", new String[] {"OPS", "SRE"}))
                .simpDestMatchers("/app/members/**").access(AuthenticatedAuthorizationManager.authenticated())
                .simpDestMatchers("/app/ops/**").access(AuthenticatedAuthorizationManager.fullyAuthenticated())
                .simpDestMatchers("/app/drafts/**").access(AuthenticatedAuthorizationManager.rememberMe())
                .simpDestMatchers("/app/lobby/**").access(AuthenticatedAuthorizationManager.anonymous())
                .simpDestMatchers("/app/open/**").access(SingleResultAuthorizationManager.permitAll())
                .simpDestMatchers("/app/closed/**").access(SingleResultAuthorizationManager.denyAll())
                .simpDestMatchers("/app/vip/**").access((authentication, context) ->
                        new AuthorizationDecision(context.getVariables().isEmpty()))
                .matchers(message -> SimpMessageHeaderAccessor.getUser(message.getHeaders()) == null).hasRole("OPS")
                .simpDestMatchers("/app/chat/**").authenticated();
        return messages.build();
    }
}

@Controller
class StompRulesController {

    @MessageMapping("/admin/purge")
    @SendTo("/topic/audit/events")
    String purge(String reason) {
        return reason;
    }

    @MessageMapping("/saved/drafts")
    void drafts(String draft) {
    }

    @MessageMapping("/guest/hello")
    void hello(String name) {
    }

    @MessageMapping("/reports/run")
    void run(String report) {
    }

    @MessageMapping("/groups/sync")
    void sync(String group) {
    }

    @MessageMapping("/members/list")
    void members(String filter) {
    }

    @MessageMapping("/ops/restart")
    void restart(String service) {
    }

    @MessageMapping("/drafts/save")
    void save(String draft) {
    }

    @MessageMapping("/lobby/join")
    void join(String name) {
    }

    @MessageMapping("/open/ping")
    void ping(String text) {
    }

    @MessageMapping("/closed/legacy")
    void legacy(String text) {
    }

    @MessageMapping("/vip/lounge")
    void lounge(String text) {
    }

    @MessageMapping("/chat/send")
    void send(String text) {
    }

    @MessageMapping("/misc/echo")
    void echo(String text) {
    }
}
