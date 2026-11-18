package fixtures.webfluxmethods;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Reactive pre/post takes the GrantedAuthorityDefaults prefix but not the RoleHierarchy bean.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class ReactiveMethodsApp {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("GRP_ADMIN > GRP_STAFF");
    }

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("GRP_");
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor guardLedger() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.webfluxmethods.Ledger.*(..))");
        return new AuthorizationManagerBeforeReactiveMethodInterceptor(pointcut,
                AuthorityReactiveAuthorizationManager.hasRole("BOOKKEEPER"));
    }

    @Bean
    SecurityWebFilterChain app(ServerHttpSecurity http) {
        return http.authorizeExchange(exchange -> exchange.anyExchange().authenticated()).build();
    }
}

@Service
class Staff {

    @PreAuthorize("hasRole('STAFF')")
    Mono<String> list() {
        return Mono.just("ann");
    }

    @PostAuthorize("returnObject == authentication.name")
    Mono<String> me() {
        return Mono.just("ann");
    }

    @Secured("ROLE_STAFF")
    Mono<String> secured() {
        return Mono.just("x");
    }
}

@Service
class Ledger {

    Mono<String> balance() {
        return Mono.just("0");
    }
}

@RestController
class ReactiveMethodsController {

    private final Staff staff;
    private final Ledger ledger;

    ReactiveMethodsController(Staff staff, Ledger ledger) {
        this.staff = staff;
        this.ledger = ledger;
    }

    @GetMapping("/staff")
    Mono<String> staff() {
        return staff.list();
    }

    @GetMapping("/me")
    Mono<String> me() {
        return staff.me();
    }

    @GetMapping("/balance")
    Mono<String> balance() {
        return ledger.balance();
    }
}
