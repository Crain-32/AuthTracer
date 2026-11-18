package dev.crain.authtracer.scan.build;

import static dev.crain.authtracer.scan.build.GradleProjectTests.script;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import dev.crain.authtracer.UsageException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * Which build tool builds a directory: its Gradle wrapper or a build's above a Gradle build file, else Maven.
 * <p>
 * Stand-in build wrappers and git hooks here are POSIX shell scripts.
 */
@DisabledOnOs(OS.WINDOWS)
class BuildsTests {

    /**
     * Stands in for a build tool: prints a classes directory named after itself, where it was run, among what else
     * the JVM prints.
     */
    private static final String TOOL = """
            #!/bin/sh
            echo "Picked up JAVA_TOOL_OPTIONS: -Dfile.encoding=UTF-8"
            mkdir -p "$(basename "$0")-classes"
            echo "AUTHTRACER_CLASSES=$(pwd -P)/$(basename "$0")-classes"
            mkdir -p target/classes
            """;

    @TempDir
    Path build;

    @Test
    void aDirectoryWithoutABuildIsRejected() {
        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(UsageException.class)
                .hasMessageContaining("No Gradle wrapper, Maven wrapper or pom.xml");
    }

    @Test
    void aDirectoryThatIsntThereIsNoProject() {
        assertThatThrownBy(() -> Builds.resolve(build.resolve("missing"))).isInstanceOf(UsageException.class)
                .hasMessageStartingWith("No such project directory: ");
    }

    @Test
    void aSubprojectsBuildFileUsesTheWrapperAboveIt() throws IOException {
        script(build.resolve("gradlew"), TOOL);
        Path groovy = Files.createDirectories(build.resolve("orders"));
        Files.writeString(groovy.resolve("orders.gradle"), "plugins { id 'java' }\n");
        Path kotlin = Files.createDirectories(build.resolve("billing"));
        Files.writeString(kotlin.resolve("build.gradle.kts"), "plugins { java }\n");

        assertThat(Builds.resolve(groovy).classDirs()).containsExactly(groovy.toRealPath().resolve("gradlew-classes"));
        assertThat(Builds.resolve(kotlin).classDirs()).containsExactly(kotlin.toRealPath().resolve("gradlew-classes"));
    }

    @Test
    void aGradleBuildWithoutAWrapperIsRejected() throws IOException {
        Files.writeString(build.resolve("build.gradle"), "plugins { id 'java' }\n");

        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(UsageException.class)
                .hasMessageContaining("No Gradle wrapper, Maven wrapper or pom.xml");
    }

    @Test
    void aSettingsFileAloneIsNoGradleBuild() throws IOException {
        script(build.resolve("gradlew"), TOOL);
        Path docs = Files.createDirectories(build.resolve("docs"));
        Files.writeString(docs.resolve("settings.gradle"), "rootProject.name = 'docs'\n");

        assertThatThrownBy(() -> Builds.resolve(docs)).isInstanceOf(UsageException.class)
                .hasMessageContaining("No Gradle wrapper, Maven wrapper or pom.xml");
    }

    @Test
    void aMavenWrapperWithoutAPomIsAMavenBuild() throws IOException {
        script(build.resolve("mvnw"), TOOL);

        assertThat(Builds.resolve(build).classDirs()).containsExactly(build.resolve("target/classes"));
    }

    @Test
    void aGradleWrapperComesBeforeMaven() throws IOException {
        script(build.resolve("gradlew"), TOOL);
        script(build.resolve("mvnw"), TOOL);
        Files.writeString(build.resolve("pom.xml"), "<project/>");

        assertThat(Builds.resolve(build).classDirs()).containsExactly(build.toRealPath().resolve("gradlew-classes"));
    }
}
