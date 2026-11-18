package dev.crain.authtracer.scan.build;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.Processes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads a Maven project's (or one module's) compiled classes and runtime classpath: compiles it, and has the dependency
 * plugin write the classpath, with the project's wrapper ({@code mvnw}, in its directory or, for a module, a parent's)
 * or {@code mvn}. Classes and resources are both in {@code target/classes}.
 */
@Supports(Feature.PROJECT_BUILDS)
final class MavenProject {

    private static final Logger log = LoggerFactory.getLogger(MavenProject.class);
    private static final Duration TIMEOUT = Duration.ofMinutes(10);

    private MavenProject() {
    }

    /**
     * The nearest {@code mvnw}: a module of a multi-module build uses the root's, which finds the build's
     * {@code .mvn} by walking up from the module.
     */
    private static java.util.Optional<Path> wrapper(Path projectDir) {
        for (Path dir = projectDir.toAbsolutePath(); dir != null; dir = dir.getParent()) {
            Path wrapper = dir.resolve("mvnw");
            if (Files.isExecutable(wrapper)) {
                return java.util.Optional.of(wrapper);
            }
            if (!Files.exists(dir.resolve("pom.xml"))) {
                break;
            }
        }
        return java.util.Optional.empty();
    }

    static BuildClasspath resolve(Path projectDir) {
        String maven = wrapper(projectDir).map(Path::toString).orElse("mvn");
        log.info("Resolving classpath of {} with Maven", projectDir);
        Path classpathFile = null;
        try {
            classpathFile = Files.createTempFile("authtracer-classpath", ".txt");
            Processes.Result result = Processes.run(projectDir, TIMEOUT, List.of(maven, "-q", "-B", "-DskipTests",
                    "compile", "dependency:build-classpath", "-Dmdep.includeScope=runtime",
                    "-Dmdep.outputFile=" + classpathFile));
            String output = result.output();
            if (!result.succeeded()) {
                throw new IllegalStateException("Maven " + (result.timedOut() ? "timed out after "
                        + TIMEOUT.toMinutes() + " minutes" : "failed") + " for " + projectDir + ":\n" + output);
            }
            Path classes = projectDir.resolve("target/classes");
            if (!Files.isDirectory(classes)) {
                throw new IllegalStateException("Maven built no target/classes in " + projectDir + ":\n" + output);
            }
            List<String> entries = Arrays.stream(Files.readString(classpathFile).trim().split(File.pathSeparator))
                    .filter(entry -> !entry.isBlank()).toList();
            List<Path> libraries = entries.stream().filter(entry -> entry.endsWith(".jar")).map(Path::of).toList();
            List<String> ignored = entries.stream().filter(entry -> !entry.endsWith(".jar")).toList();
            if (!ignored.isEmpty()) {
                log.warn("{}: classpath entries that aren't jars are left out of the scan: {}", projectDir, ignored);
            }
            log.info("Classpath of {}: {} libraries", projectDir, libraries.size());
            Path webapp = projectDir.resolve("src/main/webapp");
            return new BuildClasspath(List.of(classes), Files.isDirectory(webapp) ? List.of(classes, webapp)
                    : List.of(classes), libraries);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        finally {
            if (classpathFile != null) {
                try {
                    Files.deleteIfExists(classpathFile);
                }
                catch (IOException ignored) {
                    // A temp file; nothing to do.
                }
            }
        }
    }
}
