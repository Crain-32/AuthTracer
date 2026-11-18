package dev.crain.authtracer;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.diff.DiffReport;
import dev.crain.authtracer.diff.DiffReport.Change;
import dev.crain.authtracer.diff.DiffReport.Kind;
import dev.crain.authtracer.diff.GraphDiff;
import dev.crain.authtracer.diff.SarifReport;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.ProjectScans;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The "Agentic Authorization Regressions" use case: a change to a copy of employee-service, as an agent might propose it,
 * diffed against the original.
 */
class AgenticRegressionTests {

    private static final Path SERVICES = Path.of(System.getProperty("authtracer.services.dir"));
    private static final Path GOLDEN = Path.of(System.getProperty("authtracer.golden.dir"));
    private static final Set<String> SKIPPED = Set.of("build", ".gradle", ".git", ".idea");

    private static ApplicationGraph base;

    @TempDir
    Path temp;

    @BeforeAll
    static void scanUnchangedEmployeeService() {
        base = scan(SERVICES.resolve("employee-service"), "base");
    }

    @Test
    void weakenedFieldCheckFails() {
        Path copy = copyOfEmployeeService();
        replace(copy.resolve("src/main/java/dev/crain/employeeservice/employee/Employee.java"),
                "@PreAuthorize(\"hasRole('ADMIN')\")", "@PreAuthorize(\"isAuthenticated()\")");

        DiffReport report = GraphDiff.compare(base, scan(copy, "head"));

        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.WEAKENED)
                .extracting(Change::endpoint, Change::field)
                .contains(org.assertj.core.groups.Tuple.tuple("GET /employees/{id}", "ssn"));
        assertThat(report.failed(false)).isTrue();
        // For the pull request: the annotation sits on the line the change touched.
        Path employee = copy.resolve("src/main/java/dev/crain/employeeservice/employee/Employee.java");
        int changedLine = lineOf(employee, "@PreAuthorize(\"isAuthenticated()\")");
        JsonNode results = JsonMapper.builder().build().readTree(SarifReport.write(report,
                Map.of("employee-service", copy))).at("/runs/0/results");
        assertThat(results.valueStream().filter(result -> result.get("ruleId").asString().equals("WEAKENED")))
                .isNotEmpty().allSatisfy(result -> {
                    assertThat(result.at("/locations/0/physicalLocation/artifactLocation/uri").asString())
                            .isEqualTo("src/main/java/dev/crain/employeeservice/employee/Employee.java");
                    assertThat(result.at("/locations/0/physicalLocation/region/startLine").asInt())
                            .isEqualTo(changedLine);
                });
    }

    private static int lineOf(Path file, String text) {
        try {
            List<String> lines = Files.readAllLines(file);
            for (int i = 0; i < lines.size(); i++) {
                if (lines.get(i).contains(text)) {
                    return i + 1;
                }
            }
            throw new AssertionError(text + " not in " + file);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    @Test
    void shortcutEndpointIsADiagonalEscalation() {
        Path copy = copyOfEmployeeService();
        write(copy.resolve("src/main/java/dev/crain/employeeservice/directory/DirectoryController.java"), """
                package dev.crain.employeeservice.directory;

                import dev.crain.employeeservice.employee.EmployeeRepository;
                import dev.crain.employeeservice.employee.EmployeeResponse;
                import org.springframework.web.bind.annotation.GetMapping;
                import org.springframework.web.bind.annotation.PathVariable;
                import org.springframework.web.bind.annotation.RestController;

                @RestController
                class DirectoryController {

                    private final EmployeeRepository repository;

                    DirectoryController(EmployeeRepository repository) {
                        this.repository = repository;
                    }

                    @GetMapping("/directory/{id}")
                    EmployeeResponse get(@PathVariable long id) {
                        return EmployeeResponse.from(repository.findById(id).orElseThrow());
                    }
                }
                """);

        DiffReport report = GraphDiff.compare(base, scan(copy, "head"));

        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.DIAGONAL_ESCALATION)
                .extracting(Change::endpoint, Change::field)
                .contains(org.assertj.core.groups.Tuple.tuple("GET /directory/{id}", "ssn"),
                        org.assertj.core.groups.Tuple.tuple("GET /directory/{id}", "salary"));
        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.NEW_FINDING)
                .anySatisfy(change -> assertThat(change.message()).startsWith("On GET /directory/{id}:")
                        .contains("Employee#getSsn()"));
        assertThat(report.failed(false)).isTrue();
    }

    @Test
    void weakeningInEmployeeServiceShowsUpInProfileService() {
        Path copy = copyOfEmployeeService();
        replace(copy.resolve("src/main/java/dev/crain/employeeservice/employee/Employee.java"),
                "@PreAuthorize(\"hasRole('ADMIN')\")", "@PreAuthorize(\"isAuthenticated()\")");
        ApplicationGraph profileService = GraphJson.read(GOLDEN.resolve("profile-service.json"));

        DiffReport report = GraphDiff.compare(system(profileService, base), system(profileService, scan(copy, "head")));

        assertThat(report.changes()).filteredOn(change -> change.kind() == Kind.WEAKENED)
                .extracting(Change::service, Change::endpoint, Change::field)
                .contains(org.assertj.core.groups.Tuple.tuple("profile-service", "GET /profiles/{id}", "ssnLast4"));
    }

    private static SystemGraph system(ApplicationGraph... graphs) {
        return new Linker().link(List.of(graphs), ZipkinTraces.of(List.of()));
    }

    private static ApplicationGraph scan(Path project, String revision) {
        return ProjectScans.defaultScanner().scan(ProjectScans.project(project, null, revision, List.of()));
    }

    private Path copyOfEmployeeService() {
        Path source = SERVICES.resolve("employee-service");
        Path target = temp.resolve("employee-service");
        try (Stream<Path> files = Files.walk(source)) {
            for (Path file : files.toList()) {
                Path relative = source.relativize(file);
                if (relative.getNameCount() > 0 && SKIPPED.contains(relative.getName(0).toString())) {
                    continue;
                }
                Path destination = target.resolve(relative.toString());
                if (Files.isDirectory(file)) {
                    Files.createDirectories(destination);
                }
                else {
                    Files.copy(file, destination);
                }
            }
            target.resolve("gradlew").toFile().setExecutable(true);
            return target;
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static void replace(Path file, String from, String to) {
        try {
            String content = Files.readString(file);
            assertThat(content).contains(from);
            Files.writeString(file, content.replace(from, to));
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static void write(Path file, String content) {
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, content);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
