package fixtures.spelarguments;

import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SpEL that names the method's parameters (EXPR-02) and reads the token's claims (EXPR-04): on a handler, on service
 * methods a handler passes its path variable, body, header or a request parameter to, by name, by {@code #p0} and by
 * {@code @P}; one the handlers pass different things to; and names Spring doesn't give a parameter.
 */
@Configuration
@EnableMethodSecurity
class SpelArgumentsConfig {
}

record Document(Long id, String owner, String tenant) {
}

@Component("documentRules")
class DocumentRules {

    boolean canRead(Long id) {
        return id > 0;
    }
}

@Service
class Documents {

    @PreAuthorize("@documentRules.canRead(#id)")
    Document read(Long id) {
        return new Document(id, "alice", "acme");
    }

    @PreAuthorize("#document.owner() == authentication.name")
    Document create(Document document) {
        return document;
    }

    @PreAuthorize("#p0 != null and hasRole('SEARCH')")
    List<Document> search(String query) {
        return List.of();
    }

    @PostAuthorize("returnObject.tenant() == principal.claims['tenant']"
            + " and #region == principal.getClaimAsString('region')")
    Document inTenant(@P("tenant") String tenantId, String region) {
        return new Document(1L, "alice", tenantId);
    }

    @PreAuthorize("#id != null and principal.subject == 'auditor'")
    String archive(Long id) {
        return "archived";
    }
}

@RestController
class DocumentsController {

    private final Documents documents;

    DocumentsController(Documents documents) {
        this.documents = documents;
    }

    @PreAuthorize("#owner == authentication.name")
    @GetMapping("/owners/{owner}")
    String owner(@PathVariable String owner) {
        return owner;
    }

    @GetMapping("/documents/{documentId}")
    Document read(@PathVariable("documentId") Long docId) {
        return documents.read(docId);
    }

    @PostMapping("/documents")
    Document create(@RequestBody Document document) {
        return documents.create(document);
    }

    @GetMapping("/search")
    List<Document> search(String q) {
        return documents.search(q);
    }

    @GetMapping("/tenants")
    Document inTenant(@RequestHeader("X-Tenant") String tenant, @RequestParam String region) {
        return documents.inTenant(tenant, region);
    }

    @GetMapping("/archive/{id}")
    String archive(@PathVariable Long id) {
        return documents.archive(id);
    }

    @GetMapping("/archive")
    String archiveById(@RequestParam Long id) {
        return documents.archive(id);
    }
}
