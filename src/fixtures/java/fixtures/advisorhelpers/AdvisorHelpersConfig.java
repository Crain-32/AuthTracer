package fixtures.advisorhelpers;

import jakarta.annotation.security.RolesAllowed;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.DefaultPointcutAdvisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0092: advisor beans as applications build them. Helpers build a pointcut advisor and its pointcut, and an
 * annotation advisor that the bean method then orders after {@code @Secured}; managers are given the RoleHierarchy,
 * or not; and one advisor wraps Spring's interceptor in an advisor AuthTracer doesn't read.
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = false, securedEnabled = true)
class AdvisorHelpersConfig {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_OPS");
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor guardRead() {
        return guard("execution(* fixtures.advisorhelpers.Ledger.read(..))",
                AuthorityAuthorizationManager.hasRole("CLERK"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor guardClose(RoleHierarchy hierarchy) {
        AuthorityAuthorizationManager<MethodInvocation> manager = AuthorityAuthorizationManager.hasRole("OPS");
        manager.setRoleHierarchy(hierarchy);
        return guard("execution(* fixtures.advisorhelpers.Ledger.close(..))", manager);
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor guardReopen() {
        return guard("execution(* fixtures.advisorhelpers.Ledger.reopen(..))",
                AuthorityAuthorizationManager.hasRole("OPS"));
    }

    /**
     * Turns {@code @PreAuthorize} on, after {@code @Secured}.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor preAuthorize() {
        AuthorizationManagerBeforeMethodInterceptor interceptor = preAuthorizeInterceptor();
        interceptor.setOrder(AuthorizationInterceptorsOrder.SECURED.getOrder() + 1);
        return interceptor;
    }

    /**
     * Turns the JSR-250 annotations on, deciding them with a role the RoleHierarchy widens.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor jsr250(RoleHierarchy hierarchy) {
        return AuthorizationManagerBeforeMethodInterceptor.jsr250(opsManager(hierarchy));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor wrapped() {
        return new DefaultPointcutAdvisor(new AnnotationMatchingPointcut(Service.class),
                AuthorizationManagerBeforeMethodInterceptor.secured());
    }

    private static Advisor guard(String expression, AuthorizationManager<MethodInvocation> manager) {
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut(expression), manager);
    }

    private static AspectJExpressionPointcut pointcut(String expression) {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression(expression);
        return pointcut;
    }

    private static AuthorizationManagerBeforeMethodInterceptor preAuthorizeInterceptor() {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize();
    }

    private static AuthorizationManager<MethodInvocation> opsManager(RoleHierarchy hierarchy) {
        AuthorityAuthorizationManager<MethodInvocation> manager = AuthorityAuthorizationManager.hasRole("OPS");
        manager.setRoleHierarchy(hierarchy);
        return manager;
    }
}

@RestController
class LedgerController {

    private final Ledger ledger;

    LedgerController(Ledger ledger) {
        this.ledger = ledger;
    }

    @GetMapping("/ledger")
    String read() {
        return ledger.read();
    }

    @PostMapping("/ledger/close")
    void close() {
        ledger.close();
    }

    @PostMapping("/ledger/reopen")
    void reopen() {
        ledger.reopen();
    }

    @PostMapping("/ledger/approve")
    void approve() {
        ledger.approve();
    }

    @PostMapping("/ledger/archive")
    void archive() {
        ledger.archive();
    }
}

@Service
class Ledger {

    String read() {
        return "";
    }

    void close() {
    }

    void reopen() {
    }

    @PreAuthorize("hasRole('MANAGER')")
    @Secured("ROLE_AUDITOR")
    void approve() {
    }

    @RolesAllowed("ARCHIVIST")
    void archive() {
    }
}
