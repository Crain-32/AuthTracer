package fixtures.advisors;

import fixtures.advisors.admin.AdminLedger;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AdvisorsController {

    private final ReportService reports;
    private final AuditTrail audit;
    private final AdminLedger ledger;

    AdvisorsController(ReportService reports, AuditTrail audit, AdminLedger ledger) {
        this.reports = reports;
        this.audit = audit;
        this.ledger = ledger;
    }

    @GetMapping("/admin/ledger")
    String ledger() {
        return ledger.entries();
    }

    @GetMapping("/reports")
    String reports() {
        return reports.list();
    }

    @GetMapping("/reports/secret")
    String secret() {
        return reports.secret();
    }

    @GetMapping("/reports/latest")
    String latest() {
        return reports.latest();
    }

    @GetMapping("/audit")
    String audit() {
        return audit.read();
    }
}

@Service
class ReportService {

    @PreAuthorize("hasRole('ANALYST')")
    String list() {
        return "reports";
    }

    @Secured("ROLE_ANALYST")
    String secret() {
        return "secret";
    }

    @PostAuthorize("returnObject != null")
    String latest() {
        return "latest";
    }
}

@Service
class AuditTrail {

    @RolesAllowed("AUDITOR")
    String read() {
        return "audit";
    }
}
