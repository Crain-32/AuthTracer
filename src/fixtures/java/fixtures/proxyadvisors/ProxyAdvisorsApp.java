package fixtures.proxyadvisors;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.aot.hint.AuthorizeReturnObjectHintsRegistrar;
import org.springframework.security.aot.hint.SecurityHintsRegistrar;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * The advisors Spring Security's proxy factory applies to the objects {@code @AuthorizeReturnObject} methods return:
 * every AuthorizationAdvisor bean, a pointcut advisor's and the application's own (proxyadvisorscustomized: what
 * customizers of the factory change); an AOT hint registrar naming a type erased generics hide.
 */
@Configuration
@EnableMethodSecurity
class ProxyAdvisorsConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor auditAccounts() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.proxyadvisors.Account.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("AUDITOR"));
    }

    @Bean
    static SecurityHintsRegistrar statements(AuthorizationProxyFactory proxyFactory) {
        return new AuthorizeReturnObjectHintsRegistrar(proxyFactory, Statement.class);
    }
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@interface Masked {
}

/**
 * An advisor of the application's own, on the methods annotated {@code @Masked}.
 */
@Component
class MaskingAdvisor implements AuthorizationAdvisor {

    private final Pointcut pointcut = AnnotationMatchingPointcut.forMethodAnnotation(Masked.class);

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Object result = invocation.proceed();
        return result == null ? null : "***";
    }

    @Override
    public Pointcut getPointcut() {
        return pointcut;
    }

    @Override
    public Advice getAdvice() {
        return this;
    }

    @Override
    public int getOrder() {
        return 700;
    }
}

/**
 * One whose pointcut AuthTracer doesn't read.
 */
class Unread implements AuthorizationAdvisor {

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

@Configuration
class UnreadConfig {

    @Bean
    static Unread unread() {
        return new Unread();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static AuditingAdvisor auditing() {
        return new AuditingAdvisor();
    }
}

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@interface Audited {
}

/**
 * With the infrastructure role, @EnableMethodSecurity's auto-proxy creator applies it to beans too.
 */
class AuditingAdvisor implements AuthorizationAdvisor {

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        return invocation.proceed();
    }

    @Override
    public Pointcut getPointcut() {
        return new AnnotationMatchingPointcut(Audited.class, true);
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

@Audited
@Service
class Ledger {

    public String entries() {
        return "entries";
    }
}

class Account {

    private final String email;

    Account(String email) {
        this.email = email;
    }

    @Masked
    public String getEmail() {
        return email;
    }

    public void close() {
    }
}

/**
 * Proxied, but only an erased return type says so.
 */
class Statement {

    @PreAuthorize("hasRole('ACCOUNTANT')")
    public long getBalance() {
        return 0;
    }
}

@Service
class Accounts {

    @AuthorizeReturnObject
    public Account find(long id) {
        return new Account("a@b.c");
    }

    @AuthorizeReturnObject
    public Object latest() {
        return new Statement();
    }

    /**
     * A bean method: the masking advisor doesn't run here, as nothing auto-proxies beans with it.
     */
    @Masked
    public String secret() {
        return "secret";
    }
}

@RestController
class ProxyAdvisorsController {

    private final Accounts accounts;
    private final Ledger ledger;

    ProxyAdvisorsController(Accounts accounts, Ledger ledger) {
        this.accounts = accounts;
        this.ledger = ledger;
    }

    @GetMapping("/ledger")
    String ledger() {
        return ledger.entries();
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

    @GetMapping("/secret")
    String secret() {
        return accounts.secret();
    }
}
