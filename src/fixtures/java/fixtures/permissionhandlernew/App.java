package fixtures.permissionhandlernew;

import java.io.Serializable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A MethodSecurityExpressionHandler bean of the application's own class, which may give itself an evaluator.
 */
@Configuration
@EnableMethodSecurity
class App {

    @Bean
    static MethodSecurityExpressionHandler expressionHandler() {
        return new TenantExpressionHandler();
    }
}

class TenantExpressionHandler extends DefaultMethodSecurityExpressionHandler {

    TenantExpressionHandler() {
        setPermissionEvaluator(new TenantPermissions());
    }
}

class TenantPermissions implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable id, String type, Object permission) {
        return authentication.getName().equals("owner");
    }
}

@Service
class Documents {

    @PreAuthorize("hasPermission(#id, 'Document', 'write')")
    void write(Long id) {
    }
}

@RestController
class DocumentController {

    private final Documents documents;

    DocumentController(Documents documents) {
        this.documents = documents;
    }

    @GetMapping("/documents/{id}/edit")
    String write(@PathVariable("id") Long id) {
        documents.write(id);
        return "ok";
    }
}
