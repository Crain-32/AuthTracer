package dev.crain.employeeservice;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Arrays;

import dev.crain.employeeservice.audit.CompensationViewListener;
import dev.crain.employeeservice.audit.CompensationViewListener.CompensationViewed;
import dev.crain.employeeservice.employee.SalaryChanges;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * The brokers aren't running: the Kafka publisher is a mock, and the RabbitMQ listener is called directly.
 */
@SpringBootTest(properties = { "management.tracing.export.enabled=false", "management.health.rabbit.enabled=false",
        "spring.rabbitmq.listener.simple.auto-startup=false", "spring.grpc.server.port=0" })
@AutoConfigureMockMvc
class EmployeeServiceApplicationTests {

    private static final String EMPLOYEE_QUERY = """
            {"query": "{ employee(id: 1) { id email ssn salary } }"}""";

    @Autowired
    MockMvc mvc;

    @Autowired
    CompensationViewListener compensationViews;

    @MockitoBean
    SalaryChanges salaryChanges;

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void employeesRequireAuthentication() throws Exception {
        mvc.perform(get("/employees/1")).andExpect(status().isUnauthorized());
    }

    @Test
    void employeesRequireReadScope() throws Exception {
        mvc.perform(get("/employees/1").with(user("alice", "ROLE_USER"))).andExpect(status().isForbidden());
    }

    @Test
    void userSeesMaskedSsnAndNoSalary() throws Exception {
        mvc.perform(get("/employees/1").with(user("alice", "SCOPE_employees.read", "ROLE_USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.com"))
                .andExpect(jsonPath("$.ssn").value("***-**-****"))
                .andExpect(jsonPath("$.salary").value(nullValue()));
    }

    @Test
    void auditorSeesSalaryButNotSsn() throws Exception {
        mvc.perform(get("/employees/1").with(user("carol", "SCOPE_employees.read", "ROLE_USER", "ROLE_AUDITOR")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ssn").value("***-**-****"))
                .andExpect(jsonPath("$.salary").value(85000));
    }

    @Test
    void adminSeesEverything() throws Exception {
        mvc.perform(get("/employees/1").with(user("admin", "SCOPE_employees.read", "ROLE_USER", "ROLE_ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ssn").value("123-45-6789"))
                .andExpect(jsonPath("$.salary").value(85000));
    }

    @Test
    void managersOnlyListTheirReports() throws Exception {
        mvc.perform(get("/employees").with(user("bob", "SCOPE_employees.read", "ROLE_USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].id", containsInAnyOrder(1, 4)))
                .andExpect(jsonPath("$[0].salary").value(nullValue()));
    }

    @Test
    void graphQlFieldsHaveTheSameChecks() throws Exception {
        graphQl(EMPLOYEE_QUERY, user("alice", "SCOPE_employees.read", "ROLE_USER"))
                .andExpect(jsonPath("$.data.employee.email").value("alice@example.com"))
                .andExpect(jsonPath("$.data.employee.ssn").value("***-**-****"))
                .andExpect(jsonPath("$.data.employee.salary").value(nullValue()));
        graphQl(EMPLOYEE_QUERY, user("admin", "SCOPE_employees.read", "ROLE_USER", "ROLE_ADMIN"))
                .andExpect(jsonPath("$.data.employee.ssn").value("123-45-6789"))
                .andExpect(jsonPath("$.data.employee.salary").value(85000.0));
    }

    @Test
    void graphQlNeedsTheReadScope() throws Exception {
        graphQl(EMPLOYEE_QUERY, user("alice", "ROLE_USER"))
                .andExpect(jsonPath("$.data.employee").value(nullValue()))
                .andExpect(jsonPath("$.errors[0].extensions.classification").value("FORBIDDEN"));
    }

    @Test
    void graphQlListsOnlyAManagersReports() throws Exception {
        graphQl("""
                {"query": "{ employees { id } }"}""", user("bob", "SCOPE_employees.read", "ROLE_USER"))
                .andExpect(jsonPath("$.data.employees[*].id", containsInAnyOrder("1", "4")));
    }

    @Test
    void salaryUpdatesNeedAdmin() throws Exception {
        String body = "{\"salary\": 90000}";
        mvc.perform(put("/admin/employees/4/salary").contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(user("bob", "SCOPE_employees.write", "ROLE_USER")))
                .andExpect(status().isForbidden());
        mvc.perform(put("/admin/employees/4/salary").contentType(MediaType.APPLICATION_JSON).content(body)
                        .with(user("admin", "SCOPE_employees.write", "ROLE_USER", "ROLE_ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.salary").value(90000));
        verify(salaryChanges).publish(4, new BigDecimal("70000"), new BigDecimal("90000"), "admin");
    }

    @Test
    void auditHistoryNeedsAuditor() throws Exception {
        mvc.perform(get("/audit/employees/1").with(user("alice", "ROLE_USER"))).andExpect(status().isForbidden());
        mvc.perform(get("/audit/employees/1").with(user("carol", "ROLE_USER", "ROLE_AUDITOR")))
                .andExpect(status().isOk());
    }

    @Test
    void compensationViewsFromProfileServiceAreAuditedForAuditors() throws Exception {
        compensationViews.compensationViewed(new CompensationViewed(3, "admin", Instant.now()));

        mvc.perform(get("/audit/employees/3/views").with(user("alice", "ROLE_USER"))).andExpect(status().isForbidden());
        mvc.perform(get("/audit/employees/3/views").with(user("carol", "ROLE_USER", "ROLE_AUDITOR")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].viewedBy").value("admin"));
    }

    private ResultActions graphQl(String body, JwtRequestPostProcessor user) throws Exception {
        return mvc.perform(post("/graphql").contentType(MediaType.APPLICATION_JSON).content(body).with(user))
                .andExpect(status().isOk());
    }

    private static JwtRequestPostProcessor user(String username, String... authorities) {
        return jwt().jwt(token -> token.subject(username))
                .authorities(Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toArray(GrantedAuthority[]::new));
    }
}
