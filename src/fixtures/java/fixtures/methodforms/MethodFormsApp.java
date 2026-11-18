package fixtures.methodforms;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.HandleAuthorizationDenied;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Method checks in the shapes the other fixtures don't use: on final and static methods, with a denied handler of
 * the application's own, a transaction ordered after method security, a query whose SpEL doesn't read the
 * caller, annotation templates on with the annotations written out, @PreAuthorize's interceptor published again,
 * and a second interceptor for @Secured.
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true)
@EnableTransactionManagement(order = 1000)
class MethodFormsConfig {

    @Bean
    static AnnotationTemplateExpressionDefaults templateDefaults() {
        return new AnnotationTemplateExpressionDefaults();
    }

    /**
     * @PreAuthorize's own interceptor again, with prePostEnabled on: no second requirement.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor preAuthorize() {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize();
    }

    /**
     * A second @Secured interceptor with a manager of its own, beside Spring's: both must pass.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor supervisedSecured() {
        return AuthorizationManagerBeforeMethodInterceptor.secured(AuthorityAuthorizationManager.hasRole("SUPERVISOR"));
    }
}

@Component
class MaskingHandler implements MethodAuthorizationDeniedHandler {

    @Override
    public Object handleDeniedInvocation(MethodInvocation invocation, AuthorizationResult result) {
        return "****";
    }
}

@Service
class Ledger {

    @PreAuthorize("hasRole('ADMIN')")
    public final String sealed() {
        return "sealed";
    }

    @PreAuthorize("hasRole('ADMIN')")
    public static String helper() {
        return "helper";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = MaskingHandler.class)
    public String masked() {
        return "masked";
    }

    @Secured("ROLE_CLERK")
    public String close() {
        return "closed";
    }

    @Transactional
    @PostAuthorize("returnObject != null")
    public String post() {
        return "posted";
    }
}

@Service
@HandleAuthorizationDenied(handlerClass = MaskingHandler.class)
class Vault {

    @PreAuthorize("hasRole('ADMIN')")
    public String open() {
        return "open";
    }
}

record Document(Long id, String title) {
}

interface DocumentRepository extends Repository<Document, Long> {

    @Query("select d from Document d where d.title like ?#{[0] + '%'}")
    List<Document> findByPrefix(String prefix);
}

@RestController
class MethodFormsController {

    private final Ledger ledger;
    private final Vault vault;
    private final DocumentRepository documents;

    MethodFormsController(Ledger ledger, Vault vault, DocumentRepository documents) {
        this.ledger = ledger;
        this.vault = vault;
        this.documents = documents;
    }

    @GetMapping("/sealed")
    String sealed() {
        return ledger.sealed();
    }

    @GetMapping("/helper")
    String helper() {
        return Ledger.helper();
    }

    @GetMapping("/masked")
    String masked() {
        return ledger.masked();
    }

    @GetMapping("/close")
    String close() {
        return ledger.close();
    }

    @GetMapping("/post")
    String post() {
        return ledger.post();
    }

    @GetMapping("/vault")
    String vault() {
        return vault.open();
    }

    @GetMapping("/documents")
    List<Document> documents(@RequestParam String prefix) {
        return documents.findByPrefix(prefix);
    }
}
