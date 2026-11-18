package fixtures.bootadvisorsoff;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0092: as {@code bootadvisors}, but {@code spring.aop.auto=false} turns Spring Boot's auto-proxy creator
 * off, so no advisor bean runs, not even one with the infrastructure role.
 */
@SpringBootApplication
class BootAdvisorsOffApp {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor guardCount() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.bootadvisorsoff.Stock.count(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("STOCK"));
    }
}

@Component
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class StockAdvisor implements AuthorizationAdvisor {

    private final AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();

    StockAdvisor() {
        pointcut.setExpression("execution(* fixtures.bootadvisorsoff.Stock.*(..))");
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        return invocation.proceed();
    }

    @Override
    public Pointcut getPointcut() {
        return pointcut;
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
class StockController {

    private final Stock stock;

    StockController(Stock stock) {
        this.stock = stock;
    }

    @GetMapping("/stock")
    int count() {
        return stock.count();
    }
}

@Service
class Stock {

    int count() {
        return 0;
    }
}
