package dev.crain.payrollservice.team;

import java.math.BigDecimal;

/**
 * {@code total} is computed from employee-service's {@code salary}, which employee-service guards with a field-level check.
 */
public record PayrollView(long teamId, BigDecimal total, int headcount) {
}
