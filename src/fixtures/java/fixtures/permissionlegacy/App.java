package fixtures.permissionlegacy;

import java.io.Serializable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * The legacy @EnableGlobalMethodSecurity uses the PermissionEvaluator bean.
 */
@Configuration
@SuppressWarnings("deprecation")
@EnableGlobalMethodSecurity(prePostEnabled = true)
class App {

    @Bean
    PermissionEvaluator documentPermissions() {
        return new DocumentPermissions();
    }
}

class DocumentPermissions implements PermissionEvaluator {

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

    @PreAuthorize("hasPermission(#id, 'Document', 'read') or hasRole('ADMIN')")
    String read(Long id) {
        return "document";
    }

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

    @GetMapping("/documents/{id}")
    String read(@PathVariable("id") Long id) {
        return documents.read(id);
    }

    @GetMapping("/documents/{id}/edit")
    String write(@PathVariable("id") Long id) {
        documents.write(id);
        return "ok";
    }
}
