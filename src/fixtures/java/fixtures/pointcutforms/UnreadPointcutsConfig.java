package fixtures.pointcutforms;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;

/**
 * Pointcuts AuthTracer doesn't read: designators outside its subset, an annotation pattern, typos AspectJ would refuse
 * at startup, a pointcut that isn't an expression and one the configuration supplies. Each is reported, not guessed.
 */
@Configuration
class UnreadPointcutsConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor beanNames() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("bean(*Controller)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("WEB"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor stringArguments() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms..*(..)) && args(java.lang.String)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("ARGS"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor annotatedMethods() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(@fixtures.pointcutforms.AdminOnly * *(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("ROOT"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor unclosed() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.Archive.*(..)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor singleAmpersand() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.Archive.*(..)) & within(fixtures.pointcutforms..*)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor missingOperator() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("(within(fixtures.pointcutforms.ledger..*) within(fixtures.pointcutforms.reports..*))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor danglingOperator() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("within(fixtures.pointcutforms.ledger..*) and");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor extraParenthesis() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.Archive.*(..)))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor noParameters() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.Archive.*)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor methodReference() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.pointcutforms.Archive#fetch(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor missingReturnType() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(fixtures.pointcutforms.Archive.fetch(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    /**
     * A simple name, or a binding to an advice parameter: the type isn't in the expression.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor shortAnnotationName() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("@annotation(AdminOnly)");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole("TYPO"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor annotationMatching() {
        return new AuthorizationManagerBeforeMethodInterceptor(AnnotationMatchingPointcut.forMethodAnnotation(
                AdminOnly.class), AuthorityAuthorizationManager.hasRole("ROOT"));
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor configured(@Value("${archive.pointcut}") String expression) {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression(expression);
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("ARCHIVIST"));
    }
}
