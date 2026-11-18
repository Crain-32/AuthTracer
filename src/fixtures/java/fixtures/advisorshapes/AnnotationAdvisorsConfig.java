package fixtures.advisorshapes;

import org.springframework.aop.Advisor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.Jsr250AuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Every annotation is off, and an advisor bean turns each back on: Spring Security's own interceptors, its managers
 * given a handler or hierarchy, and a lambda that decides {@code @Secured} itself. AspectJ auto-proxying applies
 * every advisor bean, so none needs the infrastructure role.
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = false)
@EnableAspectJAutoProxy
class AnnotationAdvisorsConfig {

    @Bean
    static Advisor preFilter() {
        return new PreFilterAuthorizationMethodInterceptor();
    }

    @Bean
    static Advisor postFilter() {
        return new PostFilterAuthorizationMethodInterceptor();
    }

    @Bean
    static Advisor preAuthorize(MethodSecurityExpressionHandler expressionHandler) {
        PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
        manager.setExpressionHandler(expressionHandler);
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(manager);
    }

    @Bean
    static Advisor postAuthorize() {
        return AuthorizationManagerAfterMethodInterceptor.postAuthorize();
    }

    @Bean
    static Advisor secured() {
        return AuthorizationManagerBeforeMethodInterceptor.secured((authentication, invocation) ->
                new AuthorizationDecision(authentication.get().isAuthenticated()));
    }

    @Bean
    static Advisor jsr250(RoleHierarchy hierarchy) {
        AuthoritiesAuthorizationManager authorities = new AuthoritiesAuthorizationManager();
        authorities.setRoleHierarchy(hierarchy);
        Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();
        manager.setAuthoritiesAuthorizationManager(authorities);
        return AuthorizationManagerBeforeMethodInterceptor.jsr250(manager);
    }
}
