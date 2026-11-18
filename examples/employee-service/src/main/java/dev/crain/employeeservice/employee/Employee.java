package dev.crain.employeeservice.employee;

import java.math.BigDecimal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.HandleAuthorizationDenied;
import org.springframework.security.authorization.method.NullReturningMethodAuthorizationDeniedHandler;

/**
 * Not a record: {@code @AuthorizeReturnObject} needs a proxyable (non-final) class to apply the field-level checks below.
 */
public class Employee {

    private final long id;
    private final String firstName;
    private final String lastName;
    private final String email;
    private final String ssn;
    private BigDecimal salary;
    private final String managerUsername;

    public Employee(long id, String firstName, String lastName, String email, String ssn, BigDecimal salary,
            String managerUsername) {
        this.id = id;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.ssn = ssn;
        this.salary = salary;
        this.managerUsername = managerUsername;
    }

    public long getId() {
        return id;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = SsnMaskingHandler.class)
    public String getSsn() {
        return ssn;
    }

    @PreAuthorize("hasAnyRole('ADMIN','AUDITOR')")
    @HandleAuthorizationDenied(handlerClass = NullReturningMethodAuthorizationDeniedHandler.class)
    public BigDecimal getSalary() {
        return salary;
    }

    public String getManagerUsername() {
        return managerUsername;
    }

    void setSalary(BigDecimal salary) {
        this.salary = salary;
    }
}
