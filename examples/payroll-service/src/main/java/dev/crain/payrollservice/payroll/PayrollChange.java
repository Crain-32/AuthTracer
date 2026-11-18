package dev.crain.payrollservice.payroll;

import java.math.BigDecimal;
import java.time.Instant;

import dev.crain.payrollservice.employeeservice.EmployeeDto;

/**
 * A salary change the next pay run applies, with the employee's name as employee-service has it.
 */
public record PayrollChange(long employeeId, String employeeName, BigDecimal previous, BigDecimal current,
        String changedBy, Instant at) {

    static PayrollChange of(SalaryChange change, EmployeeDto employee) {
        return new PayrollChange(change.employeeId(), employee.firstName() + " " + employee.lastName(),
                change.previous(), change.current(), change.changedBy(), change.at());
    }
}
