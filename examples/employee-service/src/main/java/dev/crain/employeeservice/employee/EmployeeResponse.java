package dev.crain.employeeservice.employee;

import java.math.BigDecimal;

public record EmployeeResponse(long id, String firstName, String lastName, String email, String ssn, BigDecimal salary,
        String managerUsername) {

    /**
     * Reads every field through the getters, so the field-level checks on {@link Employee} apply.
     */
    public static EmployeeResponse from(Employee employee) {
        return new EmployeeResponse(employee.getId(), employee.getFirstName(), employee.getLastName(),
                employee.getEmail(), employee.getSsn(), employee.getSalary(), employee.getManagerUsername());
    }
}
