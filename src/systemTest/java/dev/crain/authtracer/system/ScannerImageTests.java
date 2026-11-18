package dev.crain.authtracer.system;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The scanner image, run as scripts/scan-artifacts.sh runs it, on the example services' Boot jars: their golden graphs,
 * and the ways it refuses to run.
 */
class ScannerImageTests {

    private static final List<String> SERVICES = List.of("profile-service", "employee-service", "identity-service",
            "payroll-service");
    private static final Path SERVICES_DIR = Path.of(System.getProperty("authtracer.services.dir"));
    private static final Path GOLDEN = Path.of(System.getProperty("authtracer.golden.dir"));
    private static final String IMAGE = System.getProperty("authtracer.scanner.image");

    @TempDir
    Path dir;

    private Path in;
    private Path out;

    @BeforeEach
    void copyTheBuiltJars() throws IOException {
        in = Files.createDirectories(dir.resolve("in"));
        out = dir.resolve("out");
        for (String service : SERVICES) {
            List<Path> jars;
            try (Stream<Path> built = Files.list(SERVICES_DIR.resolve(service).resolve("build/libs"))) {
                jars = built.filter(file -> file.getFileName().toString().startsWith(service + "-")).toList();
            }
            // The plain jars too, as build/libs has them, for the image to pass over.
            for (Path jar : jars) {
                Files.copy(jar, in.resolve(jar.getFileName()));
            }
        }
    }

    @Test
    void theBuiltJarsScanToTheGraphsTheirProjectsDo() throws IOException {
        Result result = run(Map.of("AUTHTRACER_REVISION", "golden"), "scripts/scan-artifacts.sh", in.toString(),
                out.toString(), IMAGE);

        assertThat(result.exit()).as(result.output()).isZero();
        for (String service : SERVICES) {
            assertThat(out.resolve(service + ".json")).as(service).hasSameTextualContentAs(GOLDEN.resolve(service
                    + ".json"));
        }
        assertThat(result.output()).contains("passing over employee-service-0.0.1-SNAPSHOT-plain.jar");
    }

    @Test
    void withANetworkItRefusesAndSaysHowToRunIt() throws IOException {
        Files.createDirectories(out);

        Result result = run(Map.of(), "docker", "run", "--rm", "-v", in + ":/in:ro", "-v", out + ":/out", IMAGE);

        assertThat(result.exit()).isEqualTo(2);
        assertThat(result.output()).contains("add --network none").contains("docker run --rm --network none");
    }

    @Test
    void withoutADirectoryMountedForTheGraphsItRefuses() {
        Result result = run(Map.of(), "docker", "run", "--rm", "--network", "none", "-v", in + ":/in:ro", IMAGE);

        assertThat(result.exit()).isEqualTo(2);
        assertThat(result.output()).contains("nothing is mounted at /out");
    }

    @Test
    void asRootThatCannotBecomeTheOwnerOfTheGraphsDirectoryItRefuses() {
        Result result = run(Map.of(), "docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--tmpfs",
                "/out:uid=1000,gid=1000", "-v", in + ":/in:ro", IMAGE);

        assertThat(result.exit()).isEqualTo(2);
        assertThat(result.output()).contains("add --user 1000:1000");
    }

    /**
     * A graph written before the limit stays (a scan can finish one artifact within a second); the one being written
     * when it stopped leaves no half a graph.
     */
    @Test
    void aScanPastItsTimeLimitIsStoppedWithTimeoutsExitCode() throws IOException {
        Result result = run(Map.of("AUTHTRACER_TIMEOUT", "1s"), "scripts/scan-artifacts.sh", in.toString(),
                out.toString(), IMAGE);

        assertThat(result.exit()).isEqualTo(124);
        assertThat(result.output()).contains("took longer than 1s");
        try (Stream<Path> files = Files.list(out)) {
            assertThat(files).noneMatch(file -> file.getFileName().toString().endsWith(".partial"));
        }
    }

    private record Result(int exit, String output) {
    }

    private Result run(Map<String, String> env, String... command) {
        Path log = dir.resolve("run.log");
        ProcessBuilder builder = new ProcessBuilder(new ArrayList<>(List.of(command))).redirectErrorStream(true)
                .redirectOutput(log.toFile());
        builder.environment().putAll(env);
        try {
            Process process = builder.start();
            if (!process.waitFor(5, TimeUnit.MINUTES)) {
                process.destroyForcibly();
                throw new IllegalStateException(String.join(" ", command) + " didn't finish in 5 minutes");
            }
            return new Result(process.exitValue(), Files.readString(log, StandardCharsets.UTF_8));
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Could not run " + command[0] + " (is Docker running?)", ex);
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }
}
