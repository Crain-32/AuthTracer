package dev.crain.authtracer.image;

import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.ApplicationScanner;
import dev.crain.authtracer.scan.ArtifactScans;
import dev.crain.authtracer.scan.ProjectScans;

/**
 * The scanner image's command: every Spring Boot jar and war directly in the input directory scanned, and each one's
 * graph written to the output directory as {@code <service>.json}. The entrypoint has already checked that the
 * container has no network and runs as the output's owner; this reads only its environment:
 * <ul>
 * <li>{@code AUTHTRACER_IN}, {@code AUTHTRACER_OUT}: the directories, {@code /in} and {@code /out} by default
 * <li>{@code AUTHTRACER_WORK}: where artifacts are unpacked while they're scanned, the temporary directory by
 * default
 * <li>{@code AUTHTRACER_SERVICE}: the service's name, when there is one artifact; else the name its configuration,
 * manifest or file gives it
 * <li>{@code AUTHTRACER_REVISION}: the revision, else {@code GITHUB_SHA}'s short form in a GitHub workflow, else the
 * commit or version the artifact records
 * <li>{@code AUTHTRACER_FACTS}: the services' Provided facts, {@code authtracer.yaml} in the input directory by
 * default; {@code AUTHTRACER_ORG_FACTS}: the organization's
 * </ul>
 * Exit codes: 0 every artifact scanned; 2 nothing to scan, or the environment is wrong; 3 an artifact couldn't be
 * scanned (the others were).
 */
@Supports(Feature.SCANNER_IMAGE)
public final class ScanArtifacts {

    static final int OK = 0;
    static final int USAGE = 2;
    static final int ERROR = 3;

    private ScanArtifacts() {
    }

    public static void main(String[] args) {
        System.exit(run(System.getenv(), ProjectScans.defaultScanner(), System.out, System.err));
    }

    static int run(Map<String, String> env, ApplicationScanner scanner, PrintStream out, PrintStream err) {
        try {
            Path in = Path.of(env.getOrDefault("AUTHTRACER_IN", "/in"));
            Path output = Path.of(env.getOrDefault("AUTHTRACER_OUT", "/out"));
            Path work = Path.of(env.getOrDefault("AUTHTRACER_WORK", System.getProperty("java.io.tmpdir")));
            List<Path> artifacts = artifacts(in, err);
            Optional<String> service = setting(env, "AUTHTRACER_SERVICE");
            if (service.isPresent() && artifacts.size() > 1) {
                throw new UsageException("AUTHTRACER_SERVICE names one service, and " + in + " has " + artifacts.size()
                        + " artifacts: " + names(artifacts) + ". Leave it out to name each after its configuration.");
            }
            String revision = setting(env, "AUTHTRACER_REVISION")
                    .or(() -> setting(env, "GITHUB_SHA").map(sha -> sha.substring(0, Math.min(7, sha.length()))))
                    .orElse(null);
            Optional<Path> facts = file(env, "AUTHTRACER_FACTS")
                    .or(() -> Optional.of(in.resolve(ProvidedFacts.LOCAL_FILE)));
            Optional<Path> orgFacts = file(env, "AUTHTRACER_ORG_FACTS");
            Map<String, Path> scanned = new HashMap<>();
            int status = OK;
            for (Path artifact : artifacts) {
                try {
                    ApplicationGraph graph = scan(artifact, work, scanner, service.orElse(null), revision, facts,
                            orgFacts);
                    Path previous = scanned.putIfAbsent(graph.service(), artifact);
                    if (previous != null) {
                        throw new IllegalStateException("it's " + graph.service() + " too, which "
                                + previous.getFileName() + " already is: scan one at a time, or remove the stale one");
                    }
                    Path file = write(graph, output);
                    out.println("Wrote " + file + ": " + graph.service() + " at " + graph.revision() + ", from "
                            + artifact.getFileName());
                }
                catch (RuntimeException ex) {
                    err.println("authtracer-scanner: can't scan " + artifact.getFileName() + ": " + message(ex));
                    status = ERROR;
                }
            }
            return status;
        }
        catch (UsageException ex) {
            err.println("authtracer-scanner: " + ex.getMessage());
            return USAGE;
        }
    }

    /**
     * The Boot jars and wars directly in the directory, by name; anything else there is passed over, a Gradle build's
     * {@code -plain.jar} most often.
     */
    private static List<Path> artifacts(Path in, PrintStream err) {
        if (!Files.isDirectory(in)) {
            throw new UsageException(in + " isn't a directory: mount the directory with the built jars and wars"
                    + " there.");
        }
        List<Path> archives;
        try (Stream<Path> files = Files.list(in)) {
            archives = files.filter(Files::isRegularFile).filter(file -> {
                String name = file.getFileName().toString();
                return name.endsWith(".jar") || name.endsWith(".war");
            }).sorted(Comparator.comparing(Path::getFileName)).toList();
        }
        catch (IOException ex) {
            throw new UsageException("Can't list " + in + ": " + ex.getMessage());
        }
        List<Path> artifacts = archives.stream().filter(ArtifactScans::scannable).toList();
        archives.stream().filter(archive -> !artifacts.contains(archive)).forEach(archive -> err.println(
                "authtracer-scanner: passing over " + archive.getFileName() + ", which isn't a Spring Boot jar or"
                        + " war."));
        if (artifacts.isEmpty()) {
            throw new UsageException("there's no Spring Boot jar or war in " + in + (archives.isEmpty() ? ""
                    : " (only " + names(archives) + ")") + ": mount the directory the build writes them to, such as"
                    + " build/libs or target.");
        }
        return artifacts;
    }

    private static ApplicationGraph scan(Path artifact, Path work, ApplicationScanner scanner, String service,
            String revision, Optional<Path> facts, Optional<Path> orgFacts) {
        Path unpacked;
        try {
            Files.createDirectories(work);
            unpacked = Files.createTempDirectory(work, "authtracer-");
        }
        catch (IOException ex) {
            throw new UncheckedIOException("can't unpack into " + work + ": " + ex.getMessage(), ex);
        }
        try {
            return scanner.scan(ArtifactScans.artifact(artifact, unpacked, service, revision, List.of(), facts,
                    orgFacts));
        }
        finally {
            delete(unpacked);
        }
    }

    /**
     * Writes the graph whole or not at all: a scan stopped part way (the time limit) leaves no half a graph behind.
     * Not as a temporary file, whose permissions would keep the graph from anyone but its owner.
     */
    private static Path write(ApplicationGraph graph, Path output) {
        Path file = output.resolve(fileName(graph.service()) + ".json");
        Path partial = output.resolve("." + file.getFileName() + ".partial");
        try {
            GraphJson.write(graph, partial);
            return Files.move(partial, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }
        catch (IOException ex) {
            throw new UncheckedIOException("can't write " + file + ": " + ex.getMessage(), ex);
        }
        finally {
            // Gone once it's moved; left over only when writing it failed.
            partial.toFile().delete();
        }
    }

    /**
     * The service's name as a file name: anything but letters, digits, dots, dashes and underscores replaced, so a
     * name from the artifact's configuration can't reach outside the output directory.
     */
    static String fileName(String service) {
        String name = service.replaceAll("[^A-Za-z0-9._-]", "_");
        return name.startsWith(".") ? "_" + name.substring(1) : name;
    }

    private static Optional<String> setting(Map<String, String> env, String name) {
        return Optional.ofNullable(env.get(name)).map(String::strip).filter(value -> !value.isEmpty());
    }

    /**
     * A file the environment names, which must be there: a facts file left out silently would scan without its facts.
     */
    private static Optional<Path> file(Map<String, String> env, String name) {
        Optional<Path> file = setting(env, name).map(Path::of);
        file.filter(path -> !Files.isRegularFile(path)).ifPresent(path -> {
            throw new UsageException(name + " names " + path + ", which isn't a file in the container: mount it, or"
                    + " put it in the input directory.");
        });
        return file;
    }

    private static String names(List<Path> files) {
        return String.join(", ", files.stream().map(file -> file.getFileName().toString()).toList());
    }

    /**
     * The message, and the root cause's when it says more: a broken scan names the endpoint, then what broke.
     */
    private static String message(RuntimeException ex) {
        Throwable root = ex;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String message = ex.getMessage() != null ? ex.getMessage() : ex.toString();
        return root == ex || message.contains(root.toString()) ? message : message + " (caused by " + root + ")";
    }

    private static void delete(Path dir) {
        try (Stream<Path> files = Files.walk(dir)) {
            files.sorted(Comparator.reverseOrder()).forEach(file -> file.toFile().delete());
        }
        catch (IOException | UncheckedIOException ex) {
            // Left in the temporary directory, which goes with the container.
        }
    }
}
