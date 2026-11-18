package fixtures.advisors;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Pre/post annotations are off; advisor beans turn @PreAuthorize back on, give @Secured a custom manager, and guard
 * every *Service method by pointcut. The JSR-250 advisor lacks the infrastructure role, so it never runs.
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = false)
class AdvisorsConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor preAuthorize() {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize();
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor secured() {
        return AuthorizationManagerBeforeMethodInterceptor.secured(AuthorityAuthorizationManager.hasRole("CUSTOM"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor protectServices() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisors.*Service.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("USER"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor protectAdmin() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisors.admin..*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("STAFF"));
    }

    /**
     * A subtype pattern: not read, so reported rather than matching nothing.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor protectTrails() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisors.AuditTrail+.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("AUDIT"));
    }

    @Bean
    static Advisor jsr250() {
        return AuthorizationManagerBeforeMethodInterceptor.jsr250();
    }
}
