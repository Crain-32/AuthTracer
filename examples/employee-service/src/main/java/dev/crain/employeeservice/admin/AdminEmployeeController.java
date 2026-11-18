package dev.crain.employeeservice.admin;

import java.math.BigDecimal;

import dev.crain.employeeservice.employee.EmployeeResponse;
import dev.crain.employeeservice.employee.EmployeeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/employees")
public class AdminEmployeeController {

    private static final Logger log = LoggerFactory.getLogger(AdminEmployeeController.class);

    private final EmployeeService employeeService;

    public AdminEmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @PutMapping("/{id}/salary")
    public EmployeeResponse updateSalary(@PathVariable long id, @RequestBody SalaryUpdate update,
            Authentication authentication) {
        log.info("PUT /admin/employees/{}/salary by {}", id, authentication.getName());
        return EmployeeResponse.from(employeeService.updateSalary(id, update.salary()));
    }

    public record SalaryUpdate(BigDecimal salary) {
    }
}
