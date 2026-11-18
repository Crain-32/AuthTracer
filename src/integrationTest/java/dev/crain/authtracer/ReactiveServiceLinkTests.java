package dev.crain.authtracer;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import org.junit.jupiter.api.Test;

/**
 * payroll-service (WebFlux) linked statically with profile-service and employee-service: its gRPC call reaches employee-service,
 * employee-service's Kafka messages reach it, and what it computes from employee-service's fields inherits their checks.
 */
class ReactiveServiceLinkTests {

    private static final Path GOLDEN = Path.of(System.getProperty("authtracer.golden.dir"));

    private final SystemGraph system = new Linker().link(List.of("profile-service", "employee-service", "payroll-service").stream()
            .map(service -> GraphJson.read(GOLDEN.resolve(service + ".json"))).toList(), ZipkinTraces.of(List.of()));

    @Test
    void theGrpcCallReachesEmployeeService() {
        assertThat(system.links()).anySatisfy(link -> {
            assertThat(link.from()).isEqualTo("payroll-service/egress:dev.crain.payrollservice.employeeservice.EmployeeServiceClient"
                    + "#employee(long) GRPC employees.v1.EmployeeDirectory/GetEmployee");
            assertThat(link.to()).isEqualTo("employee-service/ingress:GRPC employees.v1.EmployeeDirectory/GetEmployee");
            assertThat(link.kind()).isEqualTo(Edge.Kind.NETWORK_INFERRED);
        });
    }

    @Test
    void salaryChangesReachPayrollServiceOverKafka() {
        assertThat(system.links()).anySatisfy(link -> {
            assertThat(link.from()).isEqualTo("employee-service/egress:dev.crain.employeeservice.employee.SalaryChanges"
                    + "#publish(long,java.math.BigDecimal,java.math.BigDecimal,java.lang.String) KAFKA employee.salary-changed");
            assertThat(link.to()).isEqualTo("payroll-service/ingress:KAFKA employee.salary-changed");
            assertThat(link.kind()).isEqualTo(Edge.Kind.NETWORK_INFERRED);
        });
    }

    /**
     * payroll-service's rule for payroll asks only for ADMIN, but the total is computed from employee-service's salary, which also
     * needs the read scope on the way (employee-service's gRPC rule and {@code @PreAuthorize}) and ADMIN or AUDITOR (its field check).
     */
    @Test
    void payrollTotalInheritsEmployeeServicesChecksOnSalary() {
        Exposure total = exposure("GET /teams/{id}/payroll", "total");
        assertThat(total.requirement()).isEqualTo("ROLE_ADMIN and SCOPE_employees.read");
        assertThat(total.sources()).containsExactly("employee-service/field:dev.crain.employeeservice.employee.Employee.salary");
        assertThat(exposure("GET /teams/{id}/payroll", "").requirement()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    void leadNameIsComputedFromEmployeeServicesFields() {
        Exposure leadName = exposure("GET /teams/{id}", "leadName");
        assertThat(leadName.sources()).containsExactlyInAnyOrder(
                "employee-service/field:dev.crain.employeeservice.employee.Employee.firstName",
                "employee-service/field:dev.crain.employeeservice.employee.Employee.lastName");
        assertThat(leadName.lineage()).anySatisfy(flow -> {
            assertThat(flow.from()).isEqualTo("employee-service/field:dev.crain.employees.v1.EmployeeRecord.firstName");
            assertThat(flow.to()).isEqualTo("payroll-service/field:dev.crain.employees.v1.EmployeeRecord.firstName");
        });
    }

    private Exposure exposure(String endpoint, String field) {
        return Exposures.of(system).stream().filter(exposure -> exposure.service().equals("payroll-service")
                && exposure.endpoint().equals(endpoint) && exposure.field().equals(field)).findFirst().orElseThrow();
    }
}
