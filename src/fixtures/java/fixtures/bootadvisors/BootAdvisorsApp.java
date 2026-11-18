package fixtures.bootadvisors;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Advisor beans without {@code @EnableMethodSecurity}: Spring Boot's own auto-proxy creator applies them all with
 * AspectJ on the classpath, and only the one with the infrastructure role without it.
 */
@SpringBootApplication
class BootAdvisorsApp {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor guardCount() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.bootadvisors.Stock.count(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("STOCK"));
    }

    @Bean
    static Advisor guardReserve() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.bootadvisors.Stock.reserve(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("BUYER"));
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

    @PostMapping("/stock/reserve")
    void reserve() {
        stock.reserve();
    }
}

@Service
class Stock {

    int count() {
        return 0;
    }

    void reserve() {
    }
}
