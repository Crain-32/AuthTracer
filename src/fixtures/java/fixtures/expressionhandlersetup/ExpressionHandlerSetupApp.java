package fixtures.expressionhandlersetup;

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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * EXPR-05: a handler whose evaluation context's root is its own, set up as the handler is (its role prefix), as
 * Spring's own handler sets up the roots it makes.
 */
@Configuration
@EnableMethodSecurity
class ExpressionHandlerSetupConfig {

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        CrewExpressionHandler handler = new CrewExpressionHandler();
        handler.setDefaultRolePrefix("CREW_");
        return handler;
    }
}

class CrewExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    @Override
    public EvaluationContext createEvaluationContext(Supplier<? extends Authentication> authentication,
            MethodInvocation invocation) {
        StandardEvaluationContext context = (StandardEvaluationContext) super.createEvaluationContext(authentication,
                invocation);
        CrewRoot root = new CrewRoot(authentication);
        root.setDefaultRolePrefix(getDefaultRolePrefix());
        context.setRootObject(root);
        return context;
    }
}

class CrewRoot extends SecurityExpressionRoot<MethodInvocation> implements MethodSecurityExpressionOperations {

    private Object filterObject;
    private Object returnObject;

    CrewRoot(Supplier<? extends Authentication> authentication) {
        super(authentication, null);
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
class Shifts {

    @PreAuthorize("hasRole('PILOT')")
    String roster() {
        return "roster";
    }
}

@RestController
class ShiftController {

    private final Shifts shifts;

    ShiftController(Shifts shifts) {
        this.shifts = shifts;
    }

    @GetMapping("/roster")
    String roster() {
        return shifts.roster();
    }
}
