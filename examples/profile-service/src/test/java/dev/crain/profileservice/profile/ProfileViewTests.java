package dev.crain.profileservice.profile;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;

import dev.crain.profileservice.employeeservice.EmployeeDto;
import org.junit.jupiter.api.Test;

class ProfileViewTests {

    @Test
    void maskedFieldsFromEmployeeServiceStayMasked() {
        EmployeeDto masked = new EmployeeDto(1, "Alice", "Anders", "alice@example.com", "***-**-****", null, "bob");

        ProfileView profile = ProfileView.from(masked);

        assertThat(profile.salaryBand()).isEqualTo("UNDISCLOSED");
        assertThat(profile.ssnLast4()).isEqualTo("****");
    }

    @Test
    void salaryBands() {
        assertThat(ProfileView.salaryBand(new BigDecimal("70000"))).isEqualTo("BAND_1");
        assertThat(ProfileView.salaryBand(new BigDecimal("95000"))).isEqualTo("BAND_2");
        assertThat(ProfileView.salaryBand(new BigDecimal("120000"))).isEqualTo("BAND_3");
    }
}
