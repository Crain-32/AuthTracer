package fixtures.rsocketrules;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.rsocket.EnableRSocketSecurity;
import org.springframework.security.config.annotation.rsocket.RSocketSecurity;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeAuthorizationContext;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Mono;

@SpringBootApplication
class RSocketRulesApp {
}

/**
 * RX-13, configured as Spring Security's reference shows: rules in a lambda that captures a manager and a configured
 * route, the rest of the spec's rules, and managers of every kind given to {@code access(..)}.
 */
@Configuration
@EnableRSocketSecurity
class RSocketRulesConfig {

    @Bean
    PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket,
            @Value("${reports.region}") String region) {
        ReactiveAuthorizationManager<PayloadExchangeAuthorizationContext> auditors =
                AuthorityReactiveAuthorizationManager.hasAuthority("AUDIT");
        return rsocket.authorizePayload(authorize -> authorize
                        .setup().authenticated()
                        .route("audit").access(auditors)
                        .route("members").access(AuthenticatedReactiveAuthorizationManager.authenticated())
                        .route("legacy.*").denyAll()
                        .route("vip").access((authentication, context) -> authentication
                                .map(found -> new AuthorizationDecision(found.isAuthenticated())))
                        .route("open").access((authentication, context) -> Mono.just(new AuthorizationDecision(true)))
                        .route("reports." + region).hasRole("ANALYST")
                        .anyRequest().authenticated()
                        .anyExchange().permitAll())
                .simpleAuthentication(Customizer.withDefaults())
                .build();
    }
}

@Controller
class RulesController {

    @MessageMapping("audit")
    Mono<Void> audit(String entry) {
        return Mono.empty();
    }

    @MessageMapping("members")
    Mono<String> members() {
        return Mono.just("members");
    }

    @MessageMapping("legacy.import")
    Mono<Void> importLegacy(String data) {
        return Mono.empty();
    }

    @MessageMapping("vip")
    Mono<String> vip() {
        return Mono.just("vip");
    }

    @MessageMapping("open")
    Mono<String> open() {
        return Mono.just("open");
    }

    @MessageMapping("reports.daily")
    Mono<String> daily() {
        return Mono.just("daily");
    }
}
