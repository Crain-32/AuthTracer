package dev.crain.authtracer.system;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The example services' Kafka and RabbitMQ, from AuthTracer's compose file, as a compose project of their own on the
 * ports given: started and awaited until healthy, then removed with their data.
 */
final class Brokers implements AutoCloseable {

    private static final String PROJECT = "authtracer-system-test";

    private final Path composeFile;
    private final Map<String, String> ports;
    private final Path log;

    private Brokers(Path composeFile, Map<String, String> ports, Path log) {
        this.composeFile = composeFile;
        this.ports = ports;
        this.log = log;
    }

    static Brokers start(Path composeFile, int kafkaPort, int rabbitPort, Path logDir) {
        try {
            Files.createDirectories(logDir);
            Files.deleteIfExists(logDir.resolve("brokers.log"));
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        Brokers brokers = new Brokers(composeFile, Map.of("KAFKA_PORT", String.valueOf(kafkaPort), "RABBITMQ_PORT",
                String.valueOf(rabbitPort)), logDir.resolve("brokers.log"));
        // A first run pulls the images, which takes a while.
        if (brokers.compose(List.of("up", "-d", "--wait"), 300) != 0) {
            brokers.close();
            throw new IllegalStateException("The brokers did not start (is Docker running?); see " + brokers.log);
        }
        return brokers;
    }

    @Override
    public void close() {
        compose(List.of("down", "--volumes"), 60);
    }

    private int compose(List<String> args, long timeoutSeconds) {
        List<String> command = new ArrayList<>(List.of("docker", "compose", "-f", composeFile.toString(), "-p", PROJECT));
        command.addAll(args);
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile()));
        builder.environment().putAll(ports);
        try {
            Process process = builder.start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return -1;
            }
            return process.exitValue();
        }
        catch (IOException ex) {
            throw new UncheckedIOException("Could not run docker compose; see " + log, ex);
        }
        catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }
}
