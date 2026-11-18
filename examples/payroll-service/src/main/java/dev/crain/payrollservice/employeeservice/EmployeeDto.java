package dev.crain.payrollservice.employeeservice;

import java.math.BigDecimal;

import dev.crain.employees.v1.EmployeeRecord;

/**
 * employee-service's {@code EmployeeRecord}, as payroll-service reads it.
 *
 * @param salary {@code null} when employee-service didn't send it
 */
public record EmployeeDto(long id, String firstName, String lastName, String email, BigDecimal salary,
        String managerUsername) {

    static EmployeeDto from(EmployeeRecord record) {
        return new EmployeeDto(record.getId(), record.getFirstName(), record.getLastName(), record.getEmail(),
                record.hasSalary() ? new BigDecimal(record.getSalary()) : null, record.getManagerUsername());
    }
}
