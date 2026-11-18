package fixtures.builtproxiesunread;

import java.util.List;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A proxy factory built from a list with an advisor of the application's own, which AuthTracer doesn't read, and a
 * helper handed that factory by its caller.
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true)
class BuiltProxiesUnreadConfig {
}

class Card {

    @PreAuthorize("hasRole('CARDS')")
    public String getNumber() {
        return "4111";
    }

    @Secured("ROLE_HOLDERS")
    public String getHolder() {
        return "Ada";
    }
}

class Logging implements AuthorizationAdvisor {

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        return invocation.proceed();
    }

    @Override
    public Pointcut getPointcut() {
        return Pointcut.TRUE;
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

final class Cards {

    private Cards() {
    }

    static String number(AuthorizationProxyFactory factory) {
        return factory.proxy(new Card()).getNumber();
    }
}

@RestController
class CardController {

    private final AuthorizationProxyFactory factory = new AuthorizationAdvisorProxyFactory(
            List.of(AuthorizationManagerBeforeMethodInterceptor.preAuthorize(), new Logging()));

    @GetMapping("/listed")
    String listed() {
        return factory.proxy(new Card()).getNumber();
    }

    @GetMapping("/holder")
    String holder() {
        return factory.proxy(new Card()).getHolder();
    }

    @GetMapping("/handed")
    String handed() {
        return Cards.number(factory);
    }
}
