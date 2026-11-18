package dev.crain.authtracer.system;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A {@code java -jar} child process with its output in a log file, started and awaited until it answers HTTP.
 */
final class ManagedProcess implements AutoCloseable {

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    private final String name;
    private final Process process;
    private final Path log;

    private ManagedProcess(String name, Process process, Path log) {
        this.name = name;
        this.process = process;
        this.log = log;
    }

    static ManagedProcess start(String name, Path jar, List<String> args, Map<String, String> env, Path logDir,
            URI readiness) {
        String java = ProcessHandle.current().info().command().orElse("java");
        // C1 only: a third of the CPU to start, and the tests' few requests don't need C2's code.
        List<String> command = new ArrayList<>(List.of(java, "-XX:TieredStopAtLevel=1", "-jar", jar.toString()));
        command.addAll(args);
        try {
            Files.createDirectories(logDir);
            Path log = logDir.resolve(name + ".log");
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true)
                    .redirectOutput(log.toFile());
            builder.environment().putAll(env);
            ManagedProcess started = new ManagedProcess(name, builder.start(), log);
            started.awaitReady(readiness, Duration.ofSeconds(90));
            return started;
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private void awaitReady(URI readiness, Duration timeout) {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            if (!process.isAlive()) {
                throw new IllegalStateException(name + " exited with " + process.exitValue() + "; see " + log);
            }
            try {
                HttpResponse<Void> response = HTTP.send(HttpRequest.newBuilder(readiness).GET().build(),
                        HttpResponse.BodyHandlers.discarding());
                if (response.statusCode() == 200) {
                    return;
                }
            }
            catch (IOException ex) {
                // Not listening yet.
            }
            catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(ex);
            }
            sleep(Duration.ofMillis(500));
        }
        throw new IllegalStateException(name + " did not become ready at " + readiness + "; see " + log);
    }

    static void sleep(Duration duration) {
        try {
            Thread.sleep(duration);
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public void close() {
        process.destroy();
        try {
            if (!process.waitFor(java.util.concurrent.TimeUnit.SECONDS.toMillis(20),
                    java.util.concurrent.TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
            }
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }
}
