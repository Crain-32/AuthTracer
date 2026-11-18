package dev.crain.authtracer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.scan.Processes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * The pull-request check on a service that lives in a subdirectory of its repository, as in a monorepo.
 */
class DiffProjectTests {

    private static final Path SERVICES = Path.of(System.getProperty("authtracer.services.dir"));
    private static final Set<String> SKIPPED = Set.of("build", ".gradle", ".git", ".idea");

    @TempDir
    Path repo;

    @Test
    void theBaseRevisionIsTheSameSubdirectoryAndTheNamesAreTheOnesAskedFor() throws IOException {
        Path project = copy(SERVICES.resolve("employee-service"), repo.resolve("services/people"));
        git("init", "-q");
        Files.writeString(repo.resolve(".gitignore"), "build/\n.gradle/\n.kotlin/\n");
        git("add", "-A");
        git("commit", "-qm", "people");
        String commit = git("rev-parse", "--short", "HEAD");
        Path json = repo.resolve("build/diff.json");

        CliRunner runner = new CliRunner();
        runner.run(new DefaultApplicationArguments("diff", "--project", project.toString(), "--base-ref", "HEAD",
                "--service", "people", "--revision", "pr-7", "--json", json.toString()));

        assertThat(runner.getExitCode()).isEqualTo(CliRunner.OK);
        JsonNode report = JsonMapper.builder().build().readTree(Files.readString(json));
        assertThat(report.get("base").asString()).isEqualTo("people@HEAD@" + commit);
        assertThat(report.get("head").asString()).isEqualTo("people@pr-7");
        assertThat(report.get("changes")).isEmpty();
    }

    private static Path copy(Path source, Path target) throws IOException {
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
        }
        target.resolve("gradlew").toFile().setExecutable(true);
        return target;
    }

    private String git(String... args) {
        List<String> command = new ArrayList<>(List.of("git", "-C", repo.toString(), "-c", "user.name=test",
                "-c", "user.email=test@localhost", "-c", "commit.gpgsign=false"));
        command.addAll(List.of(args));
        Processes.Result result = Processes.run(null, Duration.ofSeconds(60), command);
        assertThat(result.succeeded()).as("git %s: %s", String.join(" ", args), result.output()).isTrue();
        return result.output().trim();
    }
}
