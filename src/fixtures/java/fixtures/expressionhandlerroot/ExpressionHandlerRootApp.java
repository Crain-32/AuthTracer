package fixtures.expressionhandlerroot;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * EXPR-05: a handler given the RoleHierarchy and no role prefix, whose subclass makes its root in
 * createSecurityExpressionRoot(Authentication, MethodInvocation), the way Spring Security 5 applications did. 7.1.1's
 * pre/post annotations never call it, so an expression calling the root's own method fails.
 */
@Configuration
@EnableMethodSecurity
class ExpressionHandlerRootConfig {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ADMIN > STAFF");
    }

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        OwnerExpressionHandler handler = new OwnerExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        handler.setDefaultRolePrefix(null);
        return handler;
    }
}

class OwnerExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    @Override
    protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
            MethodInvocation invocation) {
        return new OwnerRoot(authentication);
    }
}

class OwnerRoot extends SecurityExpressionRoot<MethodInvocation> implements MethodSecurityExpressionOperations {

    OwnerRoot(Authentication authentication) {
        super(authentication);
    }

    public boolean isOwner(Long id) {
        return id != null;
    }

    @Override
    public void setFilterObject(Object filterObject) {
    }

    @Override
    public Object getFilterObject() {
        return null;
    }

    @Override
    public void setReturnObject(Object returnObject) {
    }

    @Override
    public Object getReturnObject() {
        return null;
    }

    @Override
    public Object getThis() {
        return this;
    }
}

@Service
class Accounts {

    @PreAuthorize("hasRole('STAFF')")
    String all() {
        return "all";
    }

    @PreAuthorize("isOwner(#id)")
    String one(Long id) {
        return "one";
    }
}

@RestController
class AccountsController {

    private final Accounts accounts;

    AccountsController(Accounts accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/accounts")
    String all() {
        return accounts.all();
    }

    @GetMapping("/accounts/{id}")
    String one(@PathVariable Long id) {
        return accounts.one(id);
    }
}
