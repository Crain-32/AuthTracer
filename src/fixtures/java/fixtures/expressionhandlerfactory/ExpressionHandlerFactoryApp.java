package fixtures.expressionhandlerfactory;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * EXPR-05: a handler given the AuthorizationManagerFactory bean, and a role prefix from a property.
 */
@Configuration
@EnableMethodSecurity
class ExpressionHandlerFactoryConfig {

    @Bean
    static AuthorizationManagerFactory<MethodInvocation> authorizationManagerFactory() {
        DefaultAuthorizationManagerFactory<MethodInvocation> factory = new DefaultAuthorizationManagerFactory<>();
        factory.setRoleHierarchy(RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_STAFF"));
        return factory;
    }

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            AuthorizationManagerFactory<MethodInvocation> authorizationManagerFactory,
            @Value("${roles.prefix:ROLE_}") String prefix) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setAuthorizationManagerFactory(authorizationManagerFactory);
        handler.setDefaultRolePrefix(prefix);
        return handler;
    }
}

@Service
class Shifts {

    @PreAuthorize("hasRole('STAFF')")
    String today() {
        return "ann";
    }
}

@RestController
class ShiftsController {

    private final Shifts shifts;

    ShiftsController(Shifts shifts) {
        this.shifts = shifts;
    }

    @GetMapping("/shifts")
    String today() {
        return shifts.today();
    }
}
