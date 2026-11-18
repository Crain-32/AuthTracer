package dev.crain.employeeservice.employee;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

import dev.crain.employeeservice.audit.AuditService;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class EmployeeService {

    private final EmployeeRepository repository;
    private final AuditService auditService;
    private final SalaryChanges salaryChanges;

    public EmployeeService(EmployeeRepository repository, AuditService auditService, SalaryChanges salaryChanges) {
        this.repository = repository;
        this.auditService = auditService;
        this.salaryChanges = salaryChanges;
    }

    @PreAuthorize("hasAuthority('SCOPE_employees.read')")
    @AuthorizeReturnObject
    public Employee find(long id) {
        return repository.findById(id).orElseThrow(() -> new NoSuchElementException("employee " + id));
    }

    @PreAuthorize("hasAuthority('SCOPE_employees.read')")
    @PostFilter("hasRole('ADMIN') or filterObject.managerUsername == authentication.name")
    @AuthorizeReturnObject
    public List<Employee> list() {
        // @PostFilter removes elements in place, so it needs a mutable list.
        return new ArrayList<>(repository.findAll());
    }

    @RolesAllowed("ADMIN")
    public Employee updateSalary(long id, BigDecimal salary) {
        Employee employee = repository.findById(id).orElseThrow(() -> new NoSuchElementException("employee " + id));
        BigDecimal previous = employee.getSalary();
        employee.setSalary(salary);
        repository.save(employee);
        auditService.recordSalaryChange(id, previous, salary);
        salaryChanges.publish(id, previous, salary, SecurityContextHolder.getContext().getAuthentication().getName());
        return employee;
    }
}
