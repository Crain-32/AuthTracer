package dev.crain.payrollservice.team;

/**
 * {@code leadName} is computed from employee-service's {@code firstName} and {@code lastName}; {@code leadEmail} is employee-service's
 * {@code email} as is.
 */
public record TeamView(long teamId, String name, String leadName, String leadEmail, int size) {
}
