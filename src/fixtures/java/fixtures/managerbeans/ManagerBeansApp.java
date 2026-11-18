package fixtures.managerbeans;

import java.time.LocalTime;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AuthorizationManager beans handed to the chain method by name: one built from Spring Security's factories, one
 * written by hand, and a component that no @Bean method declares.
 */
@Configuration
@EnableWebSecurity
class ManagerBeansConfig {

    @Bean
    AuthorizationManager<RequestAuthorizationContext> auditors() {
        return AuthorityAuthorizationManager.hasAnyRole("AUDITOR", "ADMIN");
    }

    @Bean
    AuthorizationManager<RequestAuthorizationContext> operators() {
        return AuthorityAuthorizationManager.hasRole("OPS");
    }

    @Bean
    AuthorizationManager<RequestAuthorizationContext> businessHours() {
        return new BusinessHours();
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http, AuthorizationManager<RequestAuthorizationContext> operators,
            AuthorizationManager<RequestAuthorizationContext> businessHours,
            AuthorizationManager<RequestAuthorizationContext> officeNetwork,
            @Value("${security.sessions.maximum:1}") int maximumSessions) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/ops/**").access(operators)
                        .requestMatchers("/trading/**").access(businessHours)
                        .requestMatchers("/office/**").access(officeNetwork)
                        .anyRequest().authenticated())
                .sessionManagement(session -> session.maximumSessions(maximumSessions));
        return http.build();
    }
}

class BusinessHours implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return new AuthorizationDecision(LocalTime.now().getHour() >= 9 && LocalTime.now().getHour() < 17);
    }
}

@Component
class OfficeNetwork implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        return new AuthorizationDecision(context.getRequest().getRemoteAddr().startsWith("10."));
    }
}

@RestController
class ManagerBeansController {

    @GetMapping("/ops/status")
    String status() {
        return "up";
    }

    @GetMapping("/trading/orders")
    String orders() {
        return "orders";
    }

    @GetMapping("/office/printers")
    String printers() {
        return "printers";
    }
}
