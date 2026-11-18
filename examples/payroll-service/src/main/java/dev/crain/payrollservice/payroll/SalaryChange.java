package dev.crain.payrollservice.payroll;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * employee-service's {@code SalaryChanged} event, as payroll-service reads it from Kafka.
 */
public record SalaryChange(long employeeId, BigDecimal previous, BigDecimal current, String changedBy, Instant at) {
}
