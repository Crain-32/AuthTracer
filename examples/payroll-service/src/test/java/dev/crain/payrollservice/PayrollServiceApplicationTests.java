package dev.crain.payrollservice;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import dev.crain.payrollservice.employeeservice.EmployeeDto;
import dev.crain.payrollservice.employeeservice.EmployeeServiceClient;
import dev.crain.payrollservice.payroll.SalaryChange;
import dev.crain.payrollservice.payroll.SalaryChangeListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.JwtMutator;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

/**
 * Kafka isn't running: the salary-change listener is called directly.
 */
@SpringBootTest(properties = { "management.tracing.export.enabled=false", "spring.kafka.listener.auto-startup=false" })
@AutoConfigureWebTestClient
class PayrollServiceApplicationTests {

    private static final Map<Long, EmployeeDto> EMPLOYEES = Map.of(
            1L, new EmployeeDto(1, "Alice", "Anders", "alice@example.com", new BigDecimal("85000"), "bob"),
            2L, new EmployeeDto(2, "Bob", "Brown", "bob@example.com", new BigDecimal("120000"), "admin"),
            4L, new EmployeeDto(4, "Dan", "Diaz", "dan@example.com", new BigDecimal("70000"), "bob"));

    @Autowired
    WebTestClient client;

    @Autowired
    SalaryChangeListener salaryChanges;

    @MockitoBean
    EmployeeServiceClient employeeService;

    @BeforeEach
    void stubEmployeeService() {
        given(employeeService.employee(anyLong())).willAnswer(call -> Mono.justOrEmpty(EMPLOYEES.get(call.<Long>getArgument(0))));
        // As payroll-service's own token gets them: without the salary.
        given(employeeService.employeeAsPayroll(anyLong())).willAnswer(call -> Mono.justOrEmpty(EMPLOYEES.get(call.<Long>getArgument(0)))
                .map(employee -> new EmployeeDto(employee.id(), employee.firstName(), employee.lastName(), employee.email(),
                        null, employee.managerUsername())));
    }

    @Test
    void healthIsPublic() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
    }

    @Test
    void teamsRequireAuthentication() {
        client.get().uri("/teams/1").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void teamsRequireReadScope() {
        client.mutateWith(user("alice", "ROLE_USER")).get().uri("/teams/1").exchange().expectStatus().isForbidden();
    }

    @Test
    void teamIsAssembledFromEmployeeService() {
        client.mutateWith(user("alice", "SCOPE_employees.read", "ROLE_USER")).get().uri("/teams/1").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.name").isEqualTo("Platform")
                .jsonPath("$.leadName").isEqualTo("Bob Brown")
                .jsonPath("$.leadEmail").isEqualTo("bob@example.com")
                .jsonPath("$.size").isEqualTo(2);
    }

    @Test
    void payrollNeedsAdmin() {
        client.mutateWith(user("alice", "SCOPE_employees.read", "ROLE_USER")).get().uri("/teams/1/payroll").exchange()
                .expectStatus().isForbidden();
        client.mutateWith(user("admin", "SCOPE_employees.read", "ROLE_ADMIN")).get().uri("/teams/1/payroll").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.total").isEqualTo(155000).jsonPath("$.headcount").isEqualTo(2);
    }

    @Test
    void addingMembersNeedsTheWriteScopeAndAdmin() {
        client.mutateWith(user("alice", "SCOPE_employees.read", "SCOPE_employees.write", "ROLE_USER")).post()
                .uri("/teams/2/members/1").exchange().expectStatus().isForbidden();
        client.mutateWith(user("admin", "SCOPE_employees.write", "ROLE_ADMIN")).post().uri("/teams/2/members/1")
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.name").isEqualTo("Finance");
    }

    @Test
    void theDirectoryHidesPrivateTeamsFromNonAdmins() {
        client.mutateWith(user("alice", "SCOPE_employees.read", "ROLE_USER")).get().uri("/directory/teams").exchange()
                .expectStatus().isOk().expectBody().jsonPath("$.length()").isEqualTo(2);
        client.mutateWith(user("admin", "SCOPE_employees.read", "ROLE_ADMIN")).get().uri("/directory/teams").exchange()
                .expectStatus().isOk().expectBody().jsonPath("$.length()").isEqualTo(3);
    }

    @Test
    void salaryChangesFromEmployeeServiceAreListedToAdmins() {
        salaryChanges.salaryChanged(new SalaryChange(4, new BigDecimal("70000"), new BigDecimal("72000"), "admin",
                Instant.now()));

        client.mutateWith(user("alice", "SCOPE_employees.read", "ROLE_USER")).get().uri("/payroll/changes").exchange()
                .expectStatus().isForbidden();
        client.mutateWith(user("admin", "SCOPE_employees.read", "ROLE_ADMIN")).get().uri("/payroll/changes").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$[0].employeeId").isEqualTo(4).jsonPath("$[0].employeeName").isEqualTo("Dan Diaz")
                .jsonPath("$[0].current").isEqualTo(72000);
    }

    private static JwtMutator user(String username, String... authorities) {
        return mockJwt().jwt(token -> token.subject(username))
                .authorities(Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toArray(GrantedAuthority[]::new));
    }
}
