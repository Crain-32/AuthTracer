package dev.crain.authtracer.scan.build;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.Processes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads a Gradle project's (or subproject's) compiled classes and runtime classpath by running its build's wrapper
 * with AuthTracer's init script, in the project's directory. Compiles the project if needed.
 */
@Supports(Feature.PROJECT_BUILDS)
final class GradleProject {

    private static final Logger log = LoggerFactory.getLogger(GradleProject.class);
    private static final String INIT_SCRIPT = "/authtracer/classpath.init.gradle";
    private static final Duration TIMEOUT = Duration.ofMinutes(10);

    private GradleProject() {
    }

    /**
     * The nearest {@code gradlew}: a subproject of a multi-project build uses the root's, run in the subproject's
     * directory, where Gradle starts from that project.
     */
    static java.util.Optional<Path> wrapper(Path projectDir) {
        for (Path dir = projectDir.toAbsolutePath(); dir != null; dir = dir.getParent()) {
            Path wrapper = dir.resolve("gradlew");
            if (Files.isExecutable(wrapper)) {
                return java.util.Optional.of(wrapper);
            }
        }
        return java.util.Optional.empty();
    }

    static BuildClasspath resolve(Path projectDir) {
        Path wrapper = wrapper(projectDir).orElseThrow(() -> new IllegalArgumentException(
                "No executable Gradle wrapper at or above " + projectDir));
        Path initScript = extractInitScript();
        log.info("Resolving classpath of {}", projectDir);
        try {
            Processes.Result result = Processes.run(projectDir, TIMEOUT, List.of(wrapper.toString(), "-q",
                    "--console=plain", "-I", initScript.toString(), "authtracerClasspath"));
            String output = result.output();
            if (!result.succeeded()) {
                String hint = output.contains("Unsupported class file major version")
                        ? "The project's Gradle doesn't run on this JDK (" + System.getProperty("java.version")
                                + "): set JAVA_HOME to a JDK its Gradle version supports.\n" : "";
                throw new IllegalStateException(hint + "Gradle " + (result.timedOut() ? "timed out after "
                        + TIMEOUT.toMinutes() + " minutes" : "failed") + " for " + projectDir + ":\n" + output);
            }
            List<Path> classes = new ArrayList<>();
            List<Path> resources = new ArrayList<>();
            List<Path> libraries = new ArrayList<>();
            List<String> subprojects = new ArrayList<>();
            for (String line : output.lines().toList()) {
                if (line.startsWith("AUTHTRACER_SUBPROJECT=")) {
                    subprojects.add(line.substring("AUTHTRACER_SUBPROJECT=".length()));
                }
                else if (line.startsWith("AUTHTRACER_CLASSES=")) {
                    classes.addAll(paths(line.substring("AUTHTRACER_CLASSES=".length())));
                }
                else if (line.startsWith("AUTHTRACER_RESOURCES=")) {
                    resources.addAll(paths(line.substring("AUTHTRACER_RESOURCES=".length())));
                }
                else if (line.startsWith("AUTHTRACER_LIBRARIES=")) {
                    libraries.addAll(paths(line.substring("AUTHTRACER_LIBRARIES=".length())));
                }
                else if (line.startsWith("AUTHTRACER_IGNORED=") && line.length() > "AUTHTRACER_IGNORED=".length()) {
                    log.warn("{}: runtime classpath entries that aren't jars are left out of the scan: {}",
                            projectDir, line.substring("AUTHTRACER_IGNORED=".length()));
                }
            }
            if (!output.contains("AUTHTRACER_CLASSES=")) {
                return subproject(projectDir, subprojects);
            }
            if (classes.isEmpty()) {
                throw new IllegalStateException("Gradle printed no classes for " + projectDir + ":\n" + output);
            }
            log.info("Classpath of {}: {} class directories, {} resource directories, {} libraries", projectDir,
                    classes.size(), resources.size(), libraries.size());
            return new BuildClasspath(classes, resources, libraries);
        }
        finally {
            try {
                Files.deleteIfExists(initScript);
            }
            catch (IOException ignored) {
                // A temp file; nothing to do.
            }
        }
    }

    /**
     * The service of a build whose project here isn't a Java project (a multi-project build's root): its one Spring
     * Boot application, else its one Java project. More than one, and the scan has to be told which.
     */
    private static BuildClasspath subproject(Path projectDir, List<String> subprojects) {
        List<Path> applications = subprojects.stream().filter(entry -> entry.startsWith("boot="))
                .map(entry -> Path.of(entry.substring("boot=".length()))).toList();
        List<Path> candidates = !applications.isEmpty() ? applications : subprojects.stream()
                .map(entry -> Path.of(entry.substring(entry.indexOf('=') + 1))).toList();
        if (candidates.size() == 1) {
            log.info("{} is a multi-project build; scanning its only {}: {}", projectDir,
                    applications.isEmpty() ? "Java project" : "Spring Boot application", candidates.getFirst());
            return resolve(candidates.getFirst());
        }
        if (candidates.isEmpty()) {
            throw new UsageException(projectDir + " is not a Java project and has no Java subprojects");
        }
        // Gradle prints its projects' directories with symbolic links resolved (/private/var for macOS's /var).
        Path root;
        try {
            root = projectDir.toRealPath();
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        throw new UsageException(projectDir + " is a multi-project build: pass the service's directory with --project,"
                + " one of: " + String.join(", ", candidates.stream().map(dir -> root.relativize(dir).toString())
                        .toList()));
    }

    private static List<Path> paths(String classPath) {
        return Arrays.stream(classPath.split(File.pathSeparator))
                .filter(entry -> !entry.isBlank())
                .map(Path::of)
                .toList();
    }

    private static Path extractInitScript() {
        try (InputStream script = GradleProject.class.getResourceAsStream(INIT_SCRIPT)) {
            if (script == null) {
                throw new IllegalStateException("Missing resource " + INIT_SCRIPT);
            }
            Path file = Files.createTempFile("authtracer-classpath", ".init.gradle");
            Files.write(file, script.readAllBytes());
            return file;
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
