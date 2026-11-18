package fixtures.plainadvisors;

import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Plain Spring, with neither method security nor AspectJ auto-proxying: nothing applies the advisor bean.
 */
@Configuration
class PlainAdvisorsConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor guardCatalog() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.plainadvisors.Catalog.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("CURATOR"));
    }
}

@RestController
class CatalogController {

    private final Catalog catalog;

    CatalogController(Catalog catalog) {
        this.catalog = catalog;
    }

    @GetMapping("/catalog")
    String items() {
        return catalog.items();
    }
}

@Service
class Catalog {

    String items() {
        return "items";
    }
}
