package dev.crain.employeeservice.audit;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit/employees")
public class AuditController {

    private static final Logger log = LoggerFactory.getLogger(AuditController.class);

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/{id}")
    public List<AuditService.SalaryChange> history(@PathVariable long id, Authentication authentication) {
        log.info("GET /audit/employees/{} by {}", id, authentication.getName());
        return auditService.history(id);
    }

    @GetMapping("/{id}/views")
    public List<AuditService.CompensationView> views(@PathVariable long id, Authentication authentication) {
        log.info("GET /audit/employees/{}/views by {}", id, authentication.getName());
        return auditService.views(id);
    }
}
