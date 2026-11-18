package dev.crain.profileservice.admin;

import java.math.BigDecimal;

import dev.crain.profileservice.audit.CompensationAudit;
import dev.crain.profileservice.employeeservice.EmployeeDto;
import dev.crain.profileservice.employeeservice.EmployeeServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Inbound check here (ADMIN, filter chain) plus employee-service's field-level check on salary. Each view is reported
 * to employee-service's audit.
 */
@RestController
@RequestMapping("/admin/compensation")
public class CompensationController {

    private static final Logger log = LoggerFactory.getLogger(CompensationController.class);

    private final EmployeeServiceClient employeeServiceClient;
    private final CompensationAudit audit;

    public CompensationController(EmployeeServiceClient employeeServiceClient, CompensationAudit audit) {
        this.employeeServiceClient = employeeServiceClient;
        this.audit = audit;
    }

    @GetMapping("/{id}")
    public CompensationView get(@PathVariable long id, Authentication authentication) {
        log.info("GET /admin/compensation/{} by {}", id, authentication.getName());
        EmployeeDto employee = employeeServiceClient.getEmployee(id);
        audit.viewed(id, authentication.getName());
        return new CompensationView(employee.id(), employee.salary());
    }

    public record CompensationView(long employeeId, BigDecimal salary) {
    }
}
