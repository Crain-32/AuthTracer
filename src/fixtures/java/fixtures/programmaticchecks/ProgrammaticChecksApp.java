package fixtures.programmaticchecks;

import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checks the code makes itself with an AuthorizationManager (AUTHZ-11): {@code verify(..)} on an injected custom
 * manager, on a constant from Spring's factories, on a local composed of them, and on one given the RoleHierarchy;
 * {@code authorize(..)} whose result decides a throw or an early return, and one whose result only goes into a log;
 * a manager AuthTracer can't read; a check on an {@code @Async} thread, which has no caller.
 */
@Configuration
@EnableWebSecurity
@EnableAsync
class ProgrammaticChecksConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
        return http.build();
    }

    @Bean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_EDITOR");
    }
}

record Document(Long id, String owner) {
}

/**
 * Decides who may read a document.
 */
@Component
class DocumentAuthorizationManager implements AuthorizationManager<Document> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication, Document document) {
        return new AuthorizationDecision(document.owner().equals(authentication.get().getName()));
    }
}

/**
 * Hands out managers by name, which AuthTracer can't follow.
 */
@Component
class ManagerRegistry {

    AuthorizationManager<Document> named(String name) {
        return AuthorityAuthorizationManager.hasRole(name.toUpperCase());
    }
}

/**
 * Asks a delegate: what it decides is decision code, not a check of its own.
 */
@Component
class DraftsManager implements AuthorizationManager<Document> {

    private final AuthorizationManager<Document> delegate = AuthorityAuthorizationManager.hasRole("WRITER");

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication, Document document) {
        return delegate.authorize(authentication, document);
    }
}

/**
 * More shapes: a manager created in place, composed with a default decision and a negation, an injected field, a
 * role from a variable, a void method that returns early, a result nothing reads.
 */
@Service
class Drafts {

    @Autowired
    private DraftsManager drafts;

    String edit(Document document) {
        new DocumentAuthorizationManager().verify(SecurityContextHolder.getContext()::getAuthentication, document);
        return "edited";
    }

    String share(Document document) {
        AuthorizationManager<Document> sharers = AuthorizationManagers.anyOf(new AuthorizationDecision(false),
                AuthorizationManagers.not(AuthorityAuthorizationManager.hasRole("GUEST")), drafts);
        sharers.verify(SecurityContextHolder.getContext()::getAuthentication, document);
        return "shared";
    }

    String review(Document document) {
        if (!drafts.authorize(SecurityContextHolder.getContext()::getAuthentication, document).isGranted()) {
            throw new AccessDeniedException("writers only");
        }
        return "reviewed";
    }

    String tag(Document document, String team) {
        AuthorityAuthorizationManager.<Document>hasAnyRole(team, "TAGGER")
                .verify(SecurityContextHolder.getContext()::getAuthentication, document);
        return "tagged";
    }

    void delete(Document document) {
        AuthorizationResult result = AuthorityAuthorizationManager.<Document>hasRole("OWNER")
                .authorize(SecurityContextHolder.getContext()::getAuthentication, document);
        if (!result.isGranted()) {
            return;
        }
        System.out.println("deleted " + document);
    }

    String touch(Document document) {
        AuthorityAuthorizationManager.<Document>hasRole("TOUCHER").authorize(
                SecurityContextHolder.getContext()::getAuthentication, document);
        return "touched";
    }
}

@RestController
class DraftsController {

    private final Drafts drafts;

    DraftsController(Drafts drafts) {
        this.drafts = drafts;
    }

    @GetMapping("/drafts/{id}/edit")
    String edit(@PathVariable Long id) {
        return drafts.edit(new Document(id, "alice"));
    }

    @GetMapping("/drafts/{id}/share")
    String share(@PathVariable Long id) {
        return drafts.share(new Document(id, "alice"));
    }

    @GetMapping("/drafts/{id}/review")
    String review(@PathVariable Long id) {
        return drafts.review(new Document(id, "alice"));
    }

    @GetMapping("/drafts/{id}/tag/{team}")
    String tag(@PathVariable Long id, @PathVariable String team) {
        return drafts.tag(new Document(id, "alice"), team);
    }

    @GetMapping("/drafts/{id}/delete")
    String delete(@PathVariable Long id) {
        drafts.delete(new Document(id, "alice"));
        return "ok";
    }

    @GetMapping("/drafts/{id}/touch")
    String touch(@PathVariable Long id) {
        return drafts.touch(new Document(id, "alice"));
    }
}

@Service
class Indexer {

    @Async
    public void reindex(Document document) {
        AuthorityAuthorizationManager.hasRole("INDEXER").verify(SecurityContextHolder.getContext()::getAuthentication,
                document);
    }
}

@Service
class Documents {

    private static final AuthorizationManager<Object> ADMINS = AuthorityAuthorizationManager.hasRole("ADMIN");

    private final AuthorizationManager<Document> documentManager;
    private final ManagerRegistry registry;
    private final RoleHierarchy roleHierarchy;

    /**
     * Of the two manager beans, Spring hands in the one named like the parameter.
     */
    Documents(AuthorizationManager<Document> documentAuthorizationManager, ManagerRegistry registry,
            RoleHierarchy roleHierarchy) {
        this.documentManager = documentAuthorizationManager;
        this.registry = registry;
        this.roleHierarchy = roleHierarchy;
    }

    Document read(Long id) {
        Document document = new Document(id, "alice");
        documentManager.verify(() -> SecurityContextHolder.getContext().getAuthentication(), document);
        return document;
    }

    String purge() {
        ADMINS.verify(SecurityContextHolder.getContext()::getAuthentication, this);
        return "purged";
    }

    String publish(Document document) {
        AuthorizationManager<Document> publishers = AuthorizationManagers.allOf(
                AuthenticatedAuthorizationManager.fullyAuthenticated(),
                AuthorityAuthorizationManager.hasAnyRole("EDITOR", "PUBLISHER"));
        publishers.verify(SecurityContextHolder.getContext()::getAuthentication, document);
        return "published";
    }

    String review(Document document) {
        AuthorityAuthorizationManager<Document> editors = AuthorityAuthorizationManager.hasRole("EDITOR");
        editors.setRoleHierarchy(roleHierarchy);
        editors.verify(SecurityContextHolder.getContext()::getAuthentication, document);
        return "reviewed";
    }

    String archive(Document document) {
        AuthorizationResult result = AuthorityAuthorizationManager.<Document>hasAuthority("archive:write")
                .authorize(SecurityContextHolder.getContext()::getAuthentication, document);
        if (result == null || !result.isGranted()) {
            throw new AccessDeniedException("archivists only");
        }
        return "archived";
    }

    String draft(Document document) {
        AuthorizationResult result = AuthorityAuthorizationManager.<Document>hasRole("AUTHOR")
                .authorize(SecurityContextHolder.getContext()::getAuthentication, document);
        if (!result.isGranted()) {
            return "not yours";
        }
        return "drafted";
    }

    String audit(Document document) {
        AuthorizationResult result = ADMINS.authorize(SecurityContextHolder.getContext()::getAuthentication, document);
        System.out.println("audit " + result);
        return "audited";
    }

    String share(Document document, String role) {
        registry.named(role).verify(SecurityContextHolder.getContext()::getAuthentication, document);
        return "shared";
    }
}

@RestController
class DocumentsController {

    private final Documents documents;
    private final Indexer indexer;

    DocumentsController(Documents documents, Indexer indexer) {
        this.documents = documents;
        this.indexer = indexer;
    }

    @GetMapping("/documents/{id}/reindex")
    String reindex(@PathVariable Long id) {
        indexer.reindex(new Document(id, "alice"));
        return "reindexing";
    }

    @GetMapping("/documents/{id}")
    Document read(@PathVariable Long id) {
        return documents.read(id);
    }

    @GetMapping("/documents/purge")
    String purge() {
        return documents.purge();
    }

    @GetMapping("/documents/{id}/publish")
    String publish(@PathVariable Long id) {
        return documents.publish(new Document(id, "alice"));
    }

    @GetMapping("/documents/{id}/review")
    String review(@PathVariable Long id) {
        return documents.review(new Document(id, "alice"));
    }

    @GetMapping("/documents/{id}/archive")
    String archive(@PathVariable Long id) {
        return documents.archive(new Document(id, "alice"));
    }

    @GetMapping("/documents/{id}/draft")
    String draft(@PathVariable Long id) {
        return documents.draft(new Document(id, "alice"));
    }

    @GetMapping("/documents/{id}/audit")
    String audit(@PathVariable Long id) {
        return documents.audit(new Document(id, "alice"));
    }

    @GetMapping("/documents/{id}/share/{role}")
    String share(@PathVariable Long id, @PathVariable String role) {
        return documents.share(new Document(id, "alice"), role);
    }
}
