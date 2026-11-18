package fixtures.reactiveadvisors;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterReactiveMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * A reactive post-advisor, which its constructor orders last: it decides on the result before
 * {@code @PostAuthorize} does.
 */
@Configuration
@EnableReactiveMethodSecurity
class ReactiveAdvisorsConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor auditBalance() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.reactiveadvisors.Accounts.balance(..))");
        return new AuthorizationManagerAfterReactiveMethodInterceptor(pointcut,
                AuthorityReactiveAuthorizationManager.hasAuthority("SCOPE_accounts.read"));
    }
}

@RestController
class AccountsController {

    private final Accounts accounts;

    AccountsController(Accounts accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/balance")
    Mono<String> balance() {
        return accounts.balance();
    }
}

@Service
class Accounts {

    @PostAuthorize("returnObject != null")
    Mono<String> balance() {
        return Mono.just("100");
    }
}
