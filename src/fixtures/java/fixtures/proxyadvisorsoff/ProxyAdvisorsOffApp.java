package fixtures.proxyadvisorsoff;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * An AuthorizationAdvisor bean without method security: no auto-proxy creator and no proxy factory applies it.
 */
@Component
class Lone implements org.springframework.security.authorization.method.AuthorizationAdvisor {

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        return invocation.proceed();
    }

    @Override
    public Pointcut getPointcut() {
        return new AnnotationMatchingPointcut(Service.class, Deprecated.class);
    }

    @Override
    public Advice getAdvice() {
        return this;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}

@RestController
class LoneController {

    @GetMapping("/lone")
    String lone() {
        return "lone";
    }
}
