package fixtures.annotationorder;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true)
class AnnotationOrderConfig {
}

@RestController
class AnnotationOrderController {

    private final ReportService reportService;
    private final UserService userService;
    private final AuditService auditService;
    private final Rota rota;
    private final Reports reports;
    private final Vault vault;

    AnnotationOrderController(ReportService reportService, UserService userService, AuditService auditService,
            Rota rota, Reports reports, Vault vault) {
        this.reportService = reportService;
        this.userService = userService;
        this.auditService = auditService;
        this.rota = rota;
        this.reports = reports;
        this.vault = vault;
    }

    @GetMapping("/purge")
    void purge() {
        reportService.purge();
    }

    @GetMapping("/delete")
    void delete() {
        userService.delete(new User());
    }

    @GetMapping("/export")
    void export() {
        auditService.export();
    }

    @GetMapping("/rota")
    String rota() {
        return rota.view();
    }

    @GetMapping("/published")
    String published() {
        return reports.published();
    }

    @GetMapping("/drafts")
    String drafts() {
        return reports.drafts();
    }

    @GetMapping("/vault")
    String vault() {
        return vault.open();
    }
}
