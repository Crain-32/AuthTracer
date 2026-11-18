package dev.crain.authtracer.scan;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Runs the tools a scan needs (git, a project's Gradle or Maven) to their end or a timeout. Nothing is written to their
 * input, and their output is read while they run, so neither a full pipe nor a tool waiting for input outlasts the
 * timeout; a tool still running then is killed, with what it started.
 */
@Supports(Feature.PROJECT_BUILDS)
public final class Processes {

    /**
     * How long to wait for the rest of the output once the process has ended.
     */
    private static final Duration DRAIN = Duration.ofSeconds(10);

    /**
     * What a process printed, standard output and error together, and how it ended.
     *
     * @param exitCode the exit code; {@code -1} when it timed out
     */
    public record Result(int exitCode, boolean timedOut, String output) {

        public boolean succeeded() {
            return !timedOut && exitCode == 0;
        }
    }

    private Processes() {
    }

    /**
     * @param dir the working directory, {@code null} for AuthTracer's own
     * @throws UncheckedIOException when the command can't be started, e.g. the tool isn't installed
     */
    public static Result run(Path dir, Duration timeout, List<String> command) {
        Process process;
        try {
            process = new ProcessBuilder(command).directory(dir == null ? null : dir.toFile())
                    .redirectErrorStream(true).start();
            process.getOutputStream().close();
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Can't run " + String.join(" ", command), ex);
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread drain = Thread.ofVirtual().start(() -> {
            try (InputStream in = process.getInputStream()) {
                in.transferTo(output);
            }
            catch (IOException closed) {
                // The process was killed: what it printed so far is the output.
            }
        });
        try {
            boolean finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                kill(process);
            }
            drain.join(DRAIN);
            return new Result(finished ? process.exitValue() : -1, !finished, output.toString(StandardCharsets.UTF_8));
        }
        catch (InterruptedException ex) {
            kill(process);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while running " + String.join(" ", command), ex);
        }
    }

    private static void kill(Process process) {
        process.descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
    }
}
