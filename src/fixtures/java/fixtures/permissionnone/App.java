package fixtures.permissionnone;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * The legacy @EnableGlobalMethodSecurity with no PermissionEvaluator bean: hasPermission(..) denies, wherever it is
 * in the expression.
 */
@Configuration
@SuppressWarnings("deprecation")
@EnableGlobalMethodSecurity(prePostEnabled = true)
class App {
}

@Service
class Documents {

    @PreAuthorize("(hasRole('EDITOR') and isAuthenticated()) or hasPermission(#id, 'Document', 'write')")
    void write(Long id) {
    }

    @PreAuthorize("!hasPermission(#id, 'Document', 'archived')")
    String read(Long id) {
        return "document";
    }

    /**
     * Compared with true: hasPermission(..) itself.
     */
    @PreAuthorize("hasPermission(#id, 'Document', 'read') == true")
    String preview(Long id) {
        return "preview";
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

    @GetMapping("/documents/{id}")
    String read(@PathVariable("id") Long id) {
        return documents.read(id);
    }

    @GetMapping("/documents/{id}/preview")
    String preview(@PathVariable("id") Long id) {
        return documents.preview(id);
    }
}
