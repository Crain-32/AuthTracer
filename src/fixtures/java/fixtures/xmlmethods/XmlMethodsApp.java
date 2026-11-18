package fixtures.xmlmethods;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Configured by WEB-INF/spring/security.xml: method checks without annotations.
 */
@RestController
class XmlMethodsEndpoints {

    private final Ledger ledger;
    private final ReportService reports;
    private final ArchiveService archive;
    private final NoteService notes;
    private final VaultService vault;

    XmlMethodsEndpoints(Ledger ledger, ReportService reports, ArchiveService archive, NoteService notes,
            VaultService vault) {
        this.ledger = ledger;
        this.reports = reports;
        this.archive = archive;
        this.notes = notes;
        this.vault = vault;
    }

    @PostMapping("/ledger")
    String post() {
        return ledger.post();
    }

    @GetMapping("/ledger/balance")
    String balance() {
        return ledger.balance();
    }

    @GetMapping("/reports")
    String reports() {
        return reports.findAll();
    }

    @PostMapping("/reports/purge")
    String purge() {
        return reports.purge();
    }

    @GetMapping("/reports/count")
    String count() {
        return reports.count();
    }

    @GetMapping("/reports/summary")
    String summary() {
        return reports.weeklySummary();
    }

    @PostMapping("/archive")
    String store() {
        return archive.store();
    }

    @PostMapping("/vault")
    String open() {
        return vault.open();
    }

    @GetMapping("/notes")
    String notes() {
        return notes.readAll();
    }

    @GetMapping("/notes/secret")
    String secret() {
        return notes.readSecret();
    }

    @PostMapping("/notes")
    String write() {
        return notes.write();
    }
}

@Service
class Ledger {

    @PreAuthorize("hasRole('CLERK')")
    public String post() {
        return "posted";
    }

    public String balance() {
        return "0";
    }
}

/**
 * A bean of the XML's, with {@code <intercept-methods>}.
 */
class ReportService {

    public String findAll() {
        return "reports";
    }

    public String purge() {
        return "purged";
    }

    public String count() {
        return "1";
    }

    public String weeklySummary() {
        return "summary";
    }
}

class VaultService {

    public String open() {
        return "opened";
    }
}

class ArchiveService {

    public String store() {
        return "stored";
    }
}

class NoteService {

    public String readAll() {
        return "notes";
    }

    public String readSecret() {
        return "secret";
    }

    public String write() {
        return "written";
    }
}

@Component("archiveManager")
class ArchiveManager implements AuthorizationManager<MethodInvocation> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            MethodInvocation invocation) {
        return AuthorityAuthorizationManager.<MethodInvocation>hasRole("ARCHIVIST").authorize(authentication,
                invocation);
    }
}
