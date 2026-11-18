package fixtures.pointcutforms;

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
 * Pointcut advisors in the AspectJ forms applications write them, each guarding what its expression matches with a
 * role of its own. The last lacks the infrastructure role, so {@code @EnableMethodSecurity} never applies it.
 */
@Configuration
@EnableMethodSecurity
class PointcutFormsConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor services() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms..*Service.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("STAFF"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor contract() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.billing.InvoiceRepository.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("CLERK"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor adminOnly() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("@annotation(fixtures.pointcutforms.AdminOnly)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("ADMIN"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor audited() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("@within(fixtures.pointcutforms.Audited)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("AUDITOR"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor ledger() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression(
                "within(fixtures.pointcutforms.ledger..*) && !@annotation(fixtures.pointcutforms.PublicApi)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("BOOKKEEPER"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor lookups() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(public String fixtures.pointcutforms.Exporter.find*(long))"
                + " || execution(* fixtures.pointcutforms.Exporter.export(String, ..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("EXPORTER"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor monthEnd() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.Statements.*(.., int))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("ACCOUNTANT"));
    }

    /**
     * Spring reads {@code and}, {@code or} and {@code not} as {@code &&}, {@code ||} and {@code !}.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor reports() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("(within(fixtures.pointcutforms.reports.Dashboard)"
                + " or within(fixtures.pointcutforms.reports.Charts)) and not execution(* health())");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("ANALYST"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor drafts() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(protected * fixtures.pointcutforms.Drafts.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("EDITOR"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_SUPPORT)
    static Advisor support() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.Archive.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("SUPPORT"));
    }
}
