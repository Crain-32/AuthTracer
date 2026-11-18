package dev.crain.authtracer.scan.build;

import java.nio.file.Files;
import java.nio.file.Path;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Builds a project with its own build tool and reads what the scan needs: a Gradle wrapper, else Maven (its wrapper,
 * or {@code mvn} for a {@code pom.xml}). A subproject or module uses its build's wrapper, up the tree.
 */
@Supports(Feature.PROJECT_BUILDS)
public final class Builds {

    private Builds() {
    }

    public static BuildClasspath resolve(Path projectDir) {
        if (!Files.isDirectory(projectDir)) {
            throw new UsageException("No such project directory: " + projectDir);
        }
        boolean gradleBuild = gradleBuildFile(projectDir);
        if (Files.isExecutable(projectDir.resolve("gradlew"))
                || gradleBuild && GradleProject.wrapper(projectDir).isPresent()) {
            return GradleProject.resolve(projectDir);
        }
        if (Files.isExecutable(projectDir.resolve("mvnw")) || Files.isRegularFile(projectDir.resolve("pom.xml"))) {
            return MavenProject.resolve(projectDir);
        }
        throw new UsageException("No Gradle wrapper, Maven wrapper or pom.xml in " + projectDir);
    }

    /**
     * A Gradle build file: {@code build.gradle(.kts)}, or one a multi-project build names after its project
     * ({@code samples-messages-resource.gradle}).
     */
    private static boolean gradleBuildFile(Path projectDir) {
        try (var files = Files.list(projectDir)) {
            return files.map(file -> file.getFileName().toString())
                    .anyMatch(name -> (name.endsWith(".gradle") || name.endsWith(".gradle.kts"))
                            && !name.startsWith("settings."));
        }
        catch (java.io.IOException ex) {
            // Not "no build file": what is there can't be listed.
            throw new UsageException("Can't read the project directory " + projectDir + ": " + ex.getMessage());
        }
    }
}
