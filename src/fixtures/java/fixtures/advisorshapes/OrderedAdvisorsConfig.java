package fixtures.advisorshapes;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;

/**
 * Pointcut advisors placed among Spring Security's own interceptors with {@code setOrder}: before
 * {@link Payroll#approve()}'s {@code @PreAuthorize} and {@code @Secured}, and after {@link Payroll#report()}'s
 * {@code @PostAuthorize}.
 */
@Configuration
class OrderedAdvisorsConfig {

    @Bean
    static Advisor first() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.approve(..))");
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasRole("EMPLOYEE"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.FIRST.getOrder());
        return interceptor;
    }

    @Bean
    static Advisor withPreFilter() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.approve(..))");
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasRole("EMPLOYEE"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_FILTER.getOrder());
        return interceptor;
    }

    @Bean
    static Advisor afterPreAuthorize() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.approve(..))");
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasRole("EMPLOYEE"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder() + 1);
        return interceptor;
    }

    @Bean
    static Advisor between() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.approve(..))");
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasRole("EMPLOYEE"));
        interceptor.setOrder(250);
        return interceptor;
    }

    @Bean
    static Advisor beforeSecured() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.approve(..))");
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasRole("EMPLOYEE"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.SECURED.getOrder() - 1);
        return interceptor;
    }

    @Bean
    static Advisor withJsr250() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.approve(..))");
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasRole("EMPLOYEE"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.JSR250.getOrder());
        return interceptor;
    }

    /**
     * Left at the constructor's order, 0: outside every post check Spring Security registers.
     */
    @Bean
    static Advisor unordered() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.report(..))");
        return new AuthorizationManagerAfterMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasAuthority("SCOPE_payroll.read"));
    }

    @Bean
    static Advisor withSecureResult() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.report(..))");
        AuthorizationManagerAfterMethodInterceptor interceptor = new AuthorizationManagerAfterMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasAuthority("SCOPE_payroll.read"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.SECURE_RESULT.getOrder());
        return interceptor;
    }

    @Bean
    static Advisor afterPostAuthorize() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.report(..))");
        AuthorizationManagerAfterMethodInterceptor interceptor = new AuthorizationManagerAfterMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasAuthority("SCOPE_payroll.read"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.POST_AUTHORIZE.getOrder() + 1);
        return interceptor;
    }

    @Bean
    static Advisor withPostFilter() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.report(..))");
        AuthorizationManagerAfterMethodInterceptor interceptor = new AuthorizationManagerAfterMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasAuthority("SCOPE_payroll.read"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.POST_FILTER.getOrder());
        return interceptor;
    }

    @Bean
    static Advisor last() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Payroll.report(..))");
        AuthorizationManagerAfterMethodInterceptor interceptor = new AuthorizationManagerAfterMethodInterceptor(
                pointcut, AuthorityAuthorizationManager.hasAuthority("SCOPE_payroll.read"));
        interceptor.setOrder(AuthorizationInterceptorsOrder.LAST.getOrder());
        return interceptor;
    }
}
