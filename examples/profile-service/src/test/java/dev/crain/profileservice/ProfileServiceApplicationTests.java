package dev.crain.profileservice;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigDecimal;
import java.util.Arrays;

import dev.crain.profileservice.audit.CompensationAudit;
import dev.crain.profileservice.employeeservice.EmployeeDto;
import dev.crain.profileservice.employeeservice.EmployeeGraphQlClient;
import dev.crain.profileservice.employeeservice.EmployeeServiceClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * employee-service and RabbitMQ aren't running: the clients and the audit publisher are mocks.
 */
@SpringBootTest(properties = { "management.tracing.export.enabled=false", "management.health.rabbit.enabled=false" })
@AutoConfigureMockMvc
class ProfileServiceApplicationTests {

    private static final EmployeeDto ALICE = new EmployeeDto(1, "Alice", "Anders", "alice@example.com", "123-45-6789",
            new BigDecimal("85000"), "bob");

    @Autowired
    MockMvc mvc;

    @MockitoBean
    EmployeeGraphQlClient employees;

    @MockitoBean
    EmployeeServiceClient employeeServiceClient;

    @MockitoBean
    CompensationAudit audit;

    @BeforeEach
    void stubEmployeeService() {
        given(employees.employee(1)).willReturn(ALICE);
        given(employeeServiceClient.getEmployee(1)).willReturn(ALICE);
    }

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void profilesRequireAuthentication() throws Exception {
        mvc.perform(get("/profiles/1")).andExpect(status().isUnauthorized());
    }

    @Test
    void profilesRequireReadScope() throws Exception {
        mvc.perform(get("/profiles/1").with(user("alice", "ROLE_USER"))).andExpect(status().isForbidden());
    }

    @Test
    void profileIsAssembledFromEmployeeService() throws Exception {
        mvc.perform(get("/profiles/1").with(user("alice", "SCOPE_employees.read", "ROLE_USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.employeeId").value(1))
                .andExpect(jsonPath("$.displayName").value("Alice Anders"))
                .andExpect(jsonPath("$.contact.email").value("alice@example.com"))
                .andExpect(jsonPath("$.salaryBand").value("BAND_2"))
                .andExpect(jsonPath("$.ssnLast4").value("6789"));
    }

    @Test
    void compensationNeedsAdmin() throws Exception {
        mvc.perform(get("/admin/compensation/1").with(user("alice", "SCOPE_employees.read", "ROLE_USER")))
                .andExpect(status().isForbidden());
        verify(audit, never()).viewed(anyLong(), anyString());
        mvc.perform(get("/admin/compensation/1").with(user("admin", "SCOPE_employees.read", "ROLE_ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.salary").value(85000));
        verify(audit).viewed(1, "admin");
    }

    private static JwtRequestPostProcessor user(String username, String... authorities) {
        return jwt().jwt(token -> token.subject(username))
                .authorities(Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toArray(GrantedAuthority[]::new));
    }
}
