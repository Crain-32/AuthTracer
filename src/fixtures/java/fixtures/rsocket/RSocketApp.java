package fixtures.rsocket;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.rsocket.RSocketSecurity;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatcher;
import org.springframework.stereotype.Controller;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * RX-13: RSocket routes on their own port, authorized by the PayloadSocketAcceptorInterceptor bean's rules.
 */
@SpringBootApplication
@EnableReactiveMethodSecurity
class RSocketApp {

    @Bean
    PayloadSocketAcceptorInterceptor rsocketInterceptor(RSocketSecurity rsocket) {
        // The rules in a method of this class: the reference captures this.
        rsocket.authorizePayload(this::rules).simpleAuthentication(Customizer.withDefaults());
        return rsocket.build();
    }

    private void rules(RSocketSecurity.AuthorizePayloadsSpec authorize) {
        authorize.setup().hasRole("SETUP")
                .route("admin.*").hasAnyRole("ADMIN", "OPS")
                .route("profile.{name}").authenticated()
                .route("status").permitAll()
                .route("audit").access(AuthorityReactiveAuthorizationManager.hasAuthority("AUDIT"))
                .route("orders.**").authenticated()
                .matcher(exchange -> PayloadExchangeMatcher.MatchResult.match()).hasRole("CUSTOM");
    }

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
    }
}

record Profile(String name, String email) {
}

record Order(Long id, String sku) {
}

@Controller
class ProfileController {

    @MessageMapping("profile.{name}")
    Mono<Profile> profile(@DestinationVariable String name) {
        return Mono.just(new Profile(name, name + "@example.com"));
    }

    @MessageMapping("status")
    Mono<String> status() {
        return Mono.just("ok");
    }

    @MessageMapping("admin.reset")
    Mono<Void> reset() {
        return Mono.empty();
    }

    @MessageMapping("audit")
    Mono<Void> audit(String entry) {
        return Mono.empty();
    }

    @MessageMapping("metrics")
    Mono<String> metrics() {
        return Mono.just("up");
    }
}

@Controller
@MessageMapping("orders")
class OrderController {

    private final Orders orders;

    OrderController(Orders orders) {
        this.orders = orders;
    }

    @MessageMapping("list")
    Flux<Order> list() {
        return Flux.just(new Order(1L, "sku"));
    }

    @MessageMapping("cancel")
    Mono<Void> cancel(Long id) {
        return orders.cancel(id);
    }
}

@org.springframework.stereotype.Service
class Orders {

    @PreAuthorize("hasRole('ORDERS')")
    public Mono<Void> cancel(Long id) {
        return Mono.empty();
    }
}
