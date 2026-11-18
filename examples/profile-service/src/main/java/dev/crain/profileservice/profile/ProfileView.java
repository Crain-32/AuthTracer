package dev.crain.profileservice.profile;

import java.math.BigDecimal;

import dev.crain.profileservice.employeeservice.EmployeeDto;

public record ProfileView(long employeeId, String displayName, ContactInfo contact, String salaryBand,
        String ssnLast4) {

    public static ProfileView from(EmployeeDto employee) {
        return new ProfileView(
                employee.id(),
                employee.firstName() + " " + employee.lastName(),
                new ContactInfo(employee.email()),
                salaryBand(employee.salary()),
                last4(employee.ssn()));
    }

    static String salaryBand(BigDecimal salary) {
        if (salary == null) {
            return "UNDISCLOSED";
        }
        if (salary.compareTo(new BigDecimal("100000")) >= 0) {
            return "BAND_3";
        }
        return salary.compareTo(new BigDecimal("80000")) >= 0 ? "BAND_2" : "BAND_1";
    }

    static String last4(String ssn) {
        return ssn == null ? null : ssn.substring(ssn.length() - 4);
    }
}
