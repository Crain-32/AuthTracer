package fixtures.builtproxies;

import java.util.List;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.aop.Advisor;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Proxy factories the application builds itself, beside Spring Security's bean: {@code withDefaults()} applies only
 * the pre/post, filter and {@code @AuthorizeReturnObject} interceptors, with Spring's defaults; a factory built from
 * a list applies the interceptors listed. Neither applies the advisor beans.
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
class BuiltProxiesConfig {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor auditStatements() {
        AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
        pointcut.setExpression("execution(* fixtures.builtproxies.Statement.*(..))");
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut,
                AuthorityAuthorizationManager.hasRole("AUDITOR"));
    }

    /**
     * Spring's interceptors use the prefix; the defaults keep {@code ROLE_}.
     */
    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("GROUP_");
    }
}

class Statement {

    @PreAuthorize("hasRole('ACCOUNTANT')")
    public String getBalance() {
        return "100";
    }

    @Secured("ROLE_CLERK")
    public String getNumber() {
        return "42";
    }

    @RolesAllowed("TELLER")
    public String getOwner() {
        return "Ada";
    }

    @AuthorizeReturnObject
    public Entry getLatest() {
        return new Entry();
    }
}

class Entry {

    @PreAuthorize("hasRole('ACCOUNTANT')")
    public String getAmount() {
        return "10";
    }
}

@RestController
class StatementController {

    private static final AuthorizationProxyFactory SHARED = AuthorizationAdvisorProxyFactory.withDefaults();

    private final AuthorizationProxyFactory injected;
    private final AuthorizationProxyFactory own = AuthorizationAdvisorProxyFactory.withDefaults();

    StatementController(AuthorizationProxyFactory injected) {
        this.injected = injected;
    }

    @GetMapping("/spring/balance")
    String springBalance() {
        return injected.proxy(new Statement()).getBalance();
    }

    @GetMapping("/spring/number")
    String springNumber() {
        return injected.proxy(new Statement()).getNumber();
    }

    @GetMapping("/own/balance")
    String ownBalance() {
        return own.proxy(new Statement()).getBalance();
    }

    @GetMapping("/own/number")
    String ownNumber() {
        return own.proxy(new Statement()).getNumber();
    }

    @GetMapping("/own/owner")
    String ownOwner() {
        return SHARED.proxy(new Statement()).getOwner();
    }

    @GetMapping("/own/latest")
    String ownLatest() {
        return own.proxy(new Statement()).getLatest().getAmount();
    }

    @GetMapping("/local/number")
    String localNumber() {
        AuthorizationProxyFactory factory = AuthorizationAdvisorProxyFactory.withDefaults();
        return factory.proxy(new Statement()).getNumber();
    }

    @GetMapping("/listed/number")
    String listedNumber() {
        return listed().proxy(new Statement()).getNumber();
    }

    @GetMapping("/listed/balance")
    String listedBalance() {
        return listed().proxy(new Statement()).getBalance();
    }

    @GetMapping("/own/statement")
    Statement ownStatement() {
        return own.proxy(new Statement());
    }

    @GetMapping("/spring/statement")
    Statement springStatement() {
        return injected.proxy(new Statement());
    }

    private static AuthorizationProxyFactory listed() {
        return new AuthorizationAdvisorProxyFactory(List.of(AuthorizationManagerBeforeMethodInterceptor.secured()));
    }
}
