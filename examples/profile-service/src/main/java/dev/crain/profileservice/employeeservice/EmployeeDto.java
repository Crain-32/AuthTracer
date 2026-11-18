package dev.crain.profileservice.employeeservice;

import java.math.BigDecimal;

/**
 * employee-service's {@code EmployeeResponse}, as profile-service reads it.
 */
public record EmployeeDto(long id, String firstName, String lastName, String email, String ssn, BigDecimal salary,
        String managerUsername) {
}
