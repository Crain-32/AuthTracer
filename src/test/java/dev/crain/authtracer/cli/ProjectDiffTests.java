package dev.crain.authtracer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.scan.Processes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The pull-request check, {@code diff --project}, on a project whose build is a stand-in: a {@code gradlew} that
 * prints what AuthTracer's init script would, the compiled {@code projectdiffbase} or {@code projectdiffhead} fixture.
 * <p>
 * Stand-in build wrappers and git hooks here are POSIX shell scripts.
 */
@DisabledOnOs(OS.WINDOWS)
class ProjectDiffTests {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String ENDPOINT = "GET /accounts/{id}";

    @TempDir
    Path dir;

    @Test
    void aProjectIsComparedWithItsBaseAndTheReportsPointAtTheChange() throws IOException {
        Path head = project(dir.resolve("accounts"), "projectdiffhead");
        Path base = project(dir.resolve("main/accounts"), "projectdiffbase");
        Path json = dir.resolve("out/diff.json");
        Path sarif = dir.resolve("out/diff.sarif");
        Path agent = dir.resolve("out/agent.md");

        assertThat(exitCode("diff", "--project", head.toString(), "--base-project", base.toString(), "--json",
                json.toString(), "--sarif", sarif.toString(), "--agent-report", agent.toString()))
                .isEqualTo(CliRunner.FAILED);

        // Neither is a git checkout; the base is the head's service, whatever its directory is called.
        JsonNode report = JSON.readTree(Files.readString(json));
        assertThat(report.get("base").asString()).isEqualTo("accounts@base");
        assertThat(report.get("head").asString()).isEqualTo("accounts@working-tree");
        assertThat(report.get("changes").valueStream()
                .map(change -> change.get("kind").asString() + " " + change.get("endpoint").asString()))
                .contains("WEAKENED " + ENDPOINT);
        // The project's sources are at hand without --sources: the check's own line.
        JsonNode location = JSON.readTree(Files.readString(sarif)).at("/runs/0/results/0/locations/0/physicalLocation");
        assertThat(location.at("/artifactLocation/uri").asString())
                .isEqualTo("src/main/java/fixtures/projectdiffhead/AccountsController.java");
        assertThat(location.at("/region/startLine").asInt()).isEqualTo(15);
        assertThat(Files.readString(agent)).contains(ENDPOINT)
                .contains("src/main/java/fixtures/projectdiffhead/AccountsController.java:15");
    }

    @Test
    void aContextPutsBothRevisionsAmongTheOtherServices() throws IOException {
        Path head = project(dir.resolve("accounts"), "projectdiffhead");
        Path base = project(dir.resolve("base"), "projectdiffbase");
        Path context = dir.resolve("system.json");
        // The service's own graph in the context is an older scan of it: the revisions compared take its place.
        GraphJson.write(new SystemGraph(SystemGraph.SCHEMA_VERSION, List.of(graph("front", "r1"),
                graph("accounts", "stale")), List.of(), List.of(), List.of(), List.of(), List.of()), context);
        Path json = dir.resolve("diff.json");

        assertThat(exitCode("diff", "--project", head.toString(), "--base-project", base.toString(), "--context",
                context.toString(), "--json", json.toString())).isEqualTo(CliRunner.FAILED);

        JsonNode report = JSON.readTree(Files.readString(json));
        assertThat(report.get("base").asString()).isEqualTo("accounts@base, front@r1");
        assertThat(report.get("head").asString()).isEqualTo("accounts@working-tree, front@r1");
    }

    @Test
    void aBaseRefIsCheckedOutAndScannedAsTheSameService() throws IOException {
        Path repo = dir.resolve("repo");
        Path project = project(repo.resolve("services/accounts"), "projectdiffbase");
        git(repo, "init", "-q");
        git(repo, "add", "-A");
        git(repo, "commit", "-qm", "base");
        git(repo, "tag", "base");
        String baseCommit = git(repo, "rev-parse", "--short", "HEAD");
        delete(project.resolve("classes"));
        delete(project.resolve("src"));
        project(project, "projectdiffhead");
        git(repo, "add", "-A");
        git(repo, "commit", "-qm", "head");
        String headCommit = git(repo, "rev-parse", "--short", "HEAD");
        Path json = dir.resolve("diff.json");

        assertThat(exitCode("diff", "--project", project.toString(), "--base-ref", "base", "--json",
                json.toString())).isEqualTo(CliRunner.FAILED);
        JsonNode report = JSON.readTree(Files.readString(json));
        assertThat(report.get("base").asString()).isEqualTo("accounts@base@" + baseCommit);
        assertThat(report.get("head").asString()).isEqualTo("accounts@" + headCommit);

        // The head can be a revision too, recorded as asked.
        assertThat(exitCode("diff", "--project", project.toString(), "--base-ref", "base", "--head-ref", "HEAD",
                "--revision", "pr-7", "--json", json.toString())).isEqualTo(CliRunner.FAILED);
        report = JSON.readTree(Files.readString(json));
        assertThat(report.get("head").asString()).isEqualTo("accounts@pr-7");
        // Both checkouts are gone again.
        assertThat(git(repo, "worktree", "list").lines()).hasSize(1);
    }

    @Test
    void aProjectDiffNeedsABase() throws IOException {
        Path head = project(dir.resolve("accounts"), "projectdiffhead");

        assertThat(exitCode("diff", "--project", head.toString())).isEqualTo(CliRunner.USAGE);
    }

    @Test
    void aProjectIsScannedWithItsOwnBuild() throws IOException {
        Path project = project(dir.resolve("Accounts"), "projectdiffbase");
        Path out = dir.resolve("graph.json");

        assertThat(exitCode("scan", "--project", project.toString(), "--revision", "r9", "--out", out.toString()))
                .isEqualTo(CliRunner.OK);

        ApplicationGraph graph = GraphJson.read(out);
        assertThat(graph.service()).isEqualTo("accounts");
        assertThat(graph.revision()).isEqualTo("r9");
        assertThat(graph.node("ingress:" + ENDPOINT)).isPresent();
    }

    /**
     * A project of the fixture's classes and its controller's source, built by a {@code gradlew} that prints them.
     */
    private static Path project(Path project, String fixture) throws IOException {
        Files.createDirectories(project);
        Path gradlew = Files.writeString(project.resolve("gradlew"), """
                #!/bin/sh
                # Stands in for the project's Gradle: prints what AuthTracer's init script would.
                dir=$(cd "$(dirname "$0")" && pwd)
                echo "AUTHTRACER_CLASSES=$dir/classes"
                echo "AUTHTRACER_LIBRARIES=%s"
                """.formatted(System.getProperty("authtracer.fixtures.libraries")));
        assertThat(gradlew.toFile().setExecutable(true)).isTrue();
        Path classes = Files.createDirectories(project.resolve("classes/fixtures").resolve(fixture));
        for (String output : System.getProperty("authtracer.fixtures.classes").split(File.pathSeparator)) {
            Path compiled = Path.of(output, "fixtures", fixture);
            if (Files.isDirectory(compiled)) {
                try (Stream<Path> files = Files.list(compiled)) {
                    for (Path file : files.toList()) {
                        Files.copy(file, classes.resolve(file.getFileName().toString()));
                    }
                }
            }
        }
        Path source = project.resolve("src/main/java/fixtures").resolve(fixture).resolve("AccountsController.java");
        Files.createDirectories(source.getParent());
        Files.copy(Path.of("src/fixtures/java/fixtures", fixture, "AccountsController.java"), source);
        return project;
    }

    private static ApplicationGraph graph(String service, String revision) {
        return new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, service, revision, 9000, AuthoritySource.UNKNOWN,
                List.of(Ingress.of("GET", "/" + service, CodeRef.ofMethod(service + ".Controller", "get()"))),
                List.of(), List.of(), List.of(), List.of());
    }

    private static void delete(Path tree) throws IOException {
        try (Stream<Path> files = Files.walk(tree)) {
            for (Path file : files.sorted((a, b) -> b.compareTo(a)).toList()) {
                Files.delete(file);
            }
        }
    }

    private static String git(Path repo, String... args) {
        List<String> command = new ArrayList<>(List.of("git", "-C", repo.toString(), "-c", "user.name=test",
                "-c", "user.email=test@localhost", "-c", "commit.gpgsign=false"));
        command.addAll(List.of(args));
        Processes.Result result = Processes.run(null, Duration.ofSeconds(60), command);
        assertThat(result.succeeded()).as("git %s: %s", String.join(" ", args), result.output()).isTrue();
        return result.output().trim();
    }

    private static int exitCode(String... args) {
        CliRunner runner = new CliRunner();
        runner.run(new DefaultApplicationArguments(args));
        return runner.getExitCode();
    }
}
