package dev.crain.authtracer;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.ArtifactScans;
import dev.crain.authtracer.scan.ProjectScans;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Scans the real example services and compares each graph with its golden file; their built Boot jars scan to the same
 * graphs.
 */
class ExampleServicesScanTests {

    private static final Path SERVICES = Path.of(System.getProperty("authtracer.services.dir"));
    private static final Path GOLDEN = Path.of(System.getProperty("authtracer.golden.dir"));
    private static final boolean UPDATE = Boolean.parseBoolean(System.getProperty("authtracer.updateGolden"));

    @ParameterizedTest
    @ValueSource(strings = { "profile-service", "employee-service", "identity-service", "payroll-service" })
    void graphMatchesGolden(String service) throws IOException {
        ApplicationGraph graph = ProjectScans.defaultScanner()
                .scan(ProjectScans.project(SERVICES.resolve(service), null, "golden", List.of()));
        String actual = GraphJson.write(graph);
        Path golden = GOLDEN.resolve(graph.service() + ".json");
        if (UPDATE || !Files.exists(golden)) {
            Files.createDirectories(GOLDEN);
            Files.writeString(golden, actual);
        }
        assertThat(actual).as("graph of %s (rerun with -PupdateGolden=true after an intended change)", service)
                .isEqualTo(Files.readString(golden));
    }

    @ParameterizedTest
    @ValueSource(strings = { "profile-service", "employee-service", "identity-service", "payroll-service" })
    void aBuiltJarScansToTheGraphItsProjectDoes(String service, @TempDir Path work) throws IOException {
        Path project = SERVICES.resolve(service);
        Path jar;
        try (Stream<Path> built = Files.list(project.resolve("build/libs"))) {
            jar = built.filter(file -> file.getFileName().toString().startsWith(service + "-"))
                    .filter(ArtifactScans::scannable).findFirst().orElseThrow();
        }

        ApplicationGraph graph = ProjectScans.defaultScanner().scan(ArtifactScans.artifact(jar, work, null, "golden",
                List.of(), Optional.of(project.resolve(ProvidedFacts.LOCAL_FILE)), Optional.empty()));

        assertThat(GraphJson.write(graph)).as("graph of %s's %s", service, jar.getFileName())
                .isEqualTo(Files.readString(GOLDEN.resolve(service + ".json")));
    }
}
