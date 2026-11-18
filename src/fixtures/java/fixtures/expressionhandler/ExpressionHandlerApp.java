package fixtures.expressionhandler;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * EXPR-05: a MethodSecurityExpressionHandler bean of the application's own class, set up with its own role prefix and
 * trust resolver and no RoleHierarchy, whose evaluation context has a root with a method of its own. Pre/post uses it,
 * not the GrantedAuthorityDefaults and RoleHierarchy beans; the root it makes checks roles as a root starts out, with
 * ROLE_ and no hierarchy.
 */
@Configuration
@EnableMethodSecurity
class ExpressionHandlerConfig {

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_STAFF");
    }

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("GROUP_");
    }

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        TeamExpressionHandler handler = new TeamExpressionHandler();
        handler.setDefaultRolePrefix("TEAM_");
        handler.setTrustResolver(new AuthenticationTrustResolverImpl());
        return handler;
    }
}

class TeamExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    @Override
    public EvaluationContext createEvaluationContext(Supplier<? extends Authentication> authentication,
            MethodInvocation invocation) {
        StandardEvaluationContext context = (StandardEvaluationContext) super.createEvaluationContext(authentication,
                invocation);
        context.setRootObject(new TeamRoot(authentication.get()));
        return context;
    }
}

class TeamRoot extends SecurityExpressionRoot<MethodInvocation> implements MethodSecurityExpressionOperations {

    private Object filterObject;
    private Object returnObject;

    TeamRoot(Authentication authentication) {
        super(authentication);
    }

    public boolean isMember(String team) {
        return getAuthentication().getName().startsWith(team);
    }

    public boolean onCall() {
        return true;
    }

    @Override
    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    @Override
    public Object getFilterObject() {
        return filterObject;
    }

    @Override
    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    @Override
    public Object getReturnObject() {
        return returnObject;
    }

    @Override
    public Object getThis() {
        return this;
    }
}

@Service
class Rota {

    @PreAuthorize("hasRole('STAFF')")
    String today() {
        return "ann";
    }

    @PreAuthorize("isMember(#team)")
    String team(String team) {
        return team;
    }

    @PreAuthorize("onCall()")
    String pager() {
        return "bob";
    }
}

@RestController
class RotaController {

    private final Rota rota;

    RotaController(Rota rota) {
        this.rota = rota;
    }

    @GetMapping("/rota")
    String today() {
        return rota.today();
    }

    @GetMapping("/teams/{team}")
    String team(@PathVariable String team) {
        return rota.team(team);
    }

    @GetMapping("/pager")
    String pager() {
        return rota.pager();
    }
}
