package fixtures.proxyadvisorscustomized;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * FIELD-06: customizers of Spring Security's AuthorizationProxyFactory. One calls setAdvisors(..), which replaces every
 * advisor the factory applies to the objects it proxies with the one it lists: the AuthorizationAdvisor bean's check
 * and @PostAuthorize's no longer run there, @PreAuthorize's does. Another adds an advisor AuthTracer doesn't read.
 */
@Configuration
@EnableMethodSecurity
class ProxyAdvisorsCustomizedConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor auditAccounts() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.proxyadvisorscustomized.Account.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("AUDITOR"));
    }

    @Bean
    Customizer<AuthorizationAdvisorProxyFactory> preAuthorizeOnly() {
        return factory -> factory.setAdvisors(AuthorizationManagerBeforeMethodInterceptor.preAuthorize());
    }

    @Bean
    Customizer<AuthorizationAdvisorProxyFactory> withLogging() {
        return factory -> factory.addAdvisor(new Logging());
    }
}

/**
 * Logs, and decides nothing; AuthTracer doesn't read its pointcut.
 */
class Logging implements AuthorizationAdvisor {

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        return invocation.proceed();
    }

    @Override
    public Pointcut getPointcut() {
        return Pointcut.TRUE;
    }

    @Override
    public Advice getAdvice() {
        return this;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}

class Account {

    @PreAuthorize("hasRole('OWNER')")
    public String getEmail() {
        return "a@b.c";
    }

    @PostAuthorize("hasRole('AUDITOR')")
    public String getIban() {
        return "DE00";
    }

    public void close() {
    }
}

@Service
class Accounts {

    @AuthorizeReturnObject
    public Account find(long id) {
        return new Account();
    }
}

@RestController
class AccountController {

    private final Accounts accounts;

    AccountController(Accounts accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/accounts/{id}")
    Account account(@PathVariable long id) {
        return accounts.find(id);
    }

    @GetMapping("/accounts/{id}/close")
    String close(@PathVariable long id) {
        accounts.find(id).close();
        return "closed";
    }
}
