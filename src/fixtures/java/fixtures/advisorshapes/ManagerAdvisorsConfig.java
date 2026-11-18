package fixtures.advisorshapes;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AllAuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;

/**
 * A pointcut advisor for each of Spring Security's manager factories, each guarding one {@link Vault} method.
 */
@Configuration
class ManagerAdvisorsConfig {

    @Bean
    static Advisor anyRole() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.anyRole(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasAnyRole("TELLER", "MANAGER"));
    }

    @Bean
    static Advisor prefixedRole() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.prefixedRole(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasAnyRole("GROUP_", new String[] {"TELLER", "MANAGER"}));
    }

    @Bean
    static Advisor allRoles() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.allRoles(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AllAuthoritiesAuthorizationManager.hasAllRoles("TELLER", "AUDITOR"));
    }

    @Bean
    static Advisor prefixedAuthorities() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.prefixedAuthorities(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AllAuthoritiesAuthorizationManager.hasAllPrefixedAuthorities("GROUP_", "TELLER", "AUDITOR"));
    }

    @Bean
    static Advisor allAuthorities() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.allAuthorities(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AllAuthoritiesAuthorizationManager.hasAllAuthorities("SCOPE_vault.read", "SCOPE_vault.write"));
    }

    @Bean
    static Advisor anyAuthority() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.anyAuthority(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasAnyAuthority("SCOPE_vault.read", "SCOPE_vault.admin"));
    }

    @Bean
    static Advisor signedIn() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.signedIn(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthenticatedAuthorizationManager.authenticated());
    }

    @Bean
    static Advisor fully() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.fully(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthenticatedAuthorizationManager.fullyAuthenticated());
    }

    @Bean
    static Advisor remembered() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.remembered(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthenticatedAuthorizationManager.rememberMe());
    }

    @Bean
    static Advisor anonymous() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.anonymous(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthenticatedAuthorizationManager.anonymous());
    }

    @Bean
    static Advisor open() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.open(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, SingleResultAuthorizationManager.permitAll());
    }

    @Bean
    static Advisor closed() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.closed(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, SingleResultAuthorizationManager.denyAll());
    }

    /**
     * Managers composed with {@code AuthorizationManagers}.
     */
    @Bean
    static Advisor composed() {
        String expression = "execution(* fixtures.advisorshapes.Vault.composed(..))";
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression(expression);
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorizationManagers.allOf(
                AuthorityAuthorizationManager.hasRole("TELLER"),
                AuthenticatedAuthorizationManager.fullyAuthenticated()));
    }

    @Bean
    static Advisor configured(@Value("${vault.role}") String role) {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.advisorshapes.Vault.configured(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, AuthorityAuthorizationManager.hasRole(role));
    }
}
