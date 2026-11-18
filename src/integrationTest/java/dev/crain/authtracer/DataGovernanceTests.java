package dev.crain.authtracer;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.scan.ProjectScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The "Data Governance" use case (decision 0025): an Org file labels employee-service's fields and sets a policy per label.
 */
class DataGovernanceTests {

    private static final Path SERVICES = Path.of(System.getProperty("authtracer.services.dir"));

    @TempDir
    Path temp;

    @Test
    void piiExposedToNonAdminsViolatesThePolicy() throws IOException {
        Path orgFile = temp.resolve("org.yaml");
        Files.writeString(orgFile, """
                version: 1
                facts:
                  - kind: sensitive
                    field: dev.crain.employeeservice.employee.Employee.ssn
                    labels: [PII]
                  - kind: sensitive
                    field: dev.crain.employeeservice.employee.Employee.email
                    labels: [PII]
                policies:
                  - label: PII
                    requires: "hasRole('ADMIN')"
                    reason: PII is for HR admins
                """);

        ApplicationGraph employeeService = ProjectScans.defaultScanner().scan(ProjectScans.project(
                SERVICES.resolve("employee-service"), null, "policy", List.of(), Optional.of(orgFile)));
        List<Exposure> violating = Exposures.of(employeeService).stream()
                .filter(exposure -> !exposure.violations().isEmpty()).toList();

        // email has no field check, over REST, GraphQL or gRPC; ssn's is hasRole('ADMIN'), which the policy asks for, and
        // the salary update is admin-only as a whole.
        assertThat(violating).extracting(Exposure::endpoint, Exposure::field).containsExactlyInAnyOrder(
                org.assertj.core.groups.Tuple.tuple("GET /employees/{id}", "email"),
                org.assertj.core.groups.Tuple.tuple("GET /employees", "email"),
                org.assertj.core.groups.Tuple.tuple("QUERY employee", "email"),
                org.assertj.core.groups.Tuple.tuple("QUERY employees", "email"),
                org.assertj.core.groups.Tuple.tuple("GRPC employees.v1.EmployeeDirectory/GetEmployee", "email"));
        assertThat(violating).flatExtracting(Exposure::violations).allSatisfy(violation -> {
            assertThat(violation.label()).isEqualTo("PII");
            assertThat(violation.requires()).isEqualTo("ROLE_ADMIN");
        });
    }
}
