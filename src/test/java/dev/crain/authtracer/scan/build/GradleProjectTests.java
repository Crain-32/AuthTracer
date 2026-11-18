package dev.crain.authtracer.scan.build;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import dev.crain.authtracer.UsageException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * Gradle builds, run with this repository's wrapper and AuthTracer's init script: what it prints is the classpath.
 * <p>
 * Stand-in build wrappers and git hooks here are POSIX shell scripts.
 */
@DisabledOnOs(OS.WINDOWS)
class GradleProjectTests {

    @TempDir
    Path build;

    @Test
    void aJavaProjectsClassesResourcesWebappAndJarsAreRead() throws IOException {
        wrapper();
        write("settings.gradle", "rootProject.name = 'orders'\n");
        write("build.gradle", """
                plugins { id 'java' }
                dependencies { implementation files('libs/helper.jar') }
                """);
        write("src/main/java/orders/App.java", "package orders; public class App {}\n");
        write("src/main/resources/application.properties", "spring.application.name=orders\n");
        Files.createDirectories(build.resolve("src/main/webapp/WEB-INF"));
        jar(build.resolve("libs/helper.jar"));

        BuildClasspath classpath = Builds.resolve(build);

        Path root = build.toRealPath();
        assertThat(real(classpath.classDirs())).containsExactly(root.resolve("build/classes/java/main"));
        assertThat(root.resolve("build/classes/java/main/orders/App.class")).isRegularFile();
        assertThat(real(classpath.resourceDirs())).containsExactly(root.resolve("build/resources/main"),
                root.resolve("src/main/webapp"));
        assertThat(root.resolve("build/resources/main/application.properties")).isRegularFile();
        assertThat(real(classpath.libraries())).containsExactly(root.resolve("libs/helper.jar"));
    }

    @Test
    void aMultiProjectBuildsSpringBootApplicationIsTheService() throws IOException {
        wrapper();
        write("settings.gradle", "include 'app', 'lib'\n");
        write("app/build.gradle", "plugins { id 'java'; id 'org.springframework.boot' version '4.1.1' }\n");
        write("app/src/main/java/app/App.java", "package app; public class App {}\n");
        write("lib/build.gradle", "plugins { id 'java' }\n");
        write("lib/src/main/java/lib/Lib.java", "package lib; public class Lib {}\n");

        assertThat(real(Builds.resolve(build).classDirs()))
                .containsExactly(build.toRealPath().resolve("app/build/classes/java/main"));
    }

    @Test
    void aMultiProjectBuildsOnlyJavaProjectIsTheServiceFromTheRootOrItsOwnDirectory() throws IOException {
        wrapper();
        write("settings.gradle", "include 'docs', 'service'\n");
        write("docs/build.gradle", "// Not a Java project\n");
        write("service/build.gradle", "plugins { id 'java' }\n");
        write("service/src/main/java/service/App.java", "package service; public class App {}\n");
        Path classes = build.toRealPath().resolve("service/build/classes/java/main");

        assertThat(real(Builds.resolve(build).classDirs())).containsExactly(classes);
        // The subproject has no wrapper of its own: the build's, run in its directory.
        assertThat(real(Builds.resolve(build.resolve("service")).classDirs())).containsExactly(classes);
    }

    @Test
    void aBuildOfSeveralServicesHasToBeToldWhich() throws IOException {
        wrapper();
        write("settings.gradle", "include 'billing', 'orders'\n");
        write("billing/build.gradle", "plugins { id 'java' }\n");
        write("orders/build.gradle", "plugins { id 'java' }\n");

        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(UsageException.class)
                .hasMessageEndingWith(" is a multi-project build: pass the service's directory with --project,"
                        + " one of: billing, orders");
    }

    @Test
    void aBuildWithoutJavaProjectsIsNoService() throws IOException {
        wrapper();
        write("settings.gradle", "include 'docs'\n");
        write("docs/build.gradle", "// Not a Java project\n");

        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(UsageException.class)
                .hasMessageEndingWith("is not a Java project and has no Java subprojects");
    }

    @Test
    void aBuildThatFailsReportsGradlesOutput() throws IOException {
        wrapper();
        write("settings.gradle", "rootProject.name = 'broken'\n");
        write("build.gradle", "plugins { id 'java' }\n");
        write("src/main/java/broken/App.java", "package broken; public class App { int missing = ; }\n");

        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("Gradle failed for " + build).hasMessageContaining("App.java");
    }

    @Test
    void aGradleTooOldForThisJdkSaysWhichJdkToUse() throws IOException {
        // What an old Gradle prints when it can't read this JDK's class files.
        script(build.resolve("gradlew"), """
                #!/bin/sh
                echo "BUG! exception in phase 'semantic analysis': Unsupported class file major version 69"
                exit 1
                """);

        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("The project's Gradle doesn't run on this JDK (")
                .hasMessageContaining("set JAVA_HOME to a JDK its Gradle version supports")
                .hasMessageContaining("Unsupported class file major version 69");
    }

    @Test
    void aBuildThatPrintsNoClassesIsAnError() throws IOException {
        script(build.resolve("gradlew"), """
                #!/bin/sh
                echo "AUTHTRACER_CLASSES="
                echo "AUTHTRACER_RESOURCES="
                echo "AUTHTRACER_LIBRARIES="
                """);

        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("Gradle printed no classes for " + build);
    }

    /**
     * This repository's wrapper, which the tests' Gradle has already downloaded.
     */
    private void wrapper() throws IOException {
        Files.copy(Path.of("gradlew"), build.resolve("gradlew"));
        Files.createDirectories(build.resolve("gradle/wrapper"));
        for (String file : List.of("gradle-wrapper.jar", "gradle-wrapper.properties")) {
            Files.copy(Path.of("gradle/wrapper", file), build.resolve("gradle/wrapper").resolve(file));
        }
    }

    private void write(String file, String content) throws IOException {
        Path path = build.resolve(file);
        Files.createDirectories(path.getParent());
        Files.writeString(path, content);
    }

    static void script(Path file, String content) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
        assertThat(file.toFile().setExecutable(true)).isTrue();
    }

    private static void jar(Path file) throws IOException {
        Files.createDirectories(file.getParent());
        try (OutputStream out = Files.newOutputStream(file); JarOutputStream jar = new JarOutputStream(out,
                new Manifest())) {
            jar.flush();
        }
    }

    private static List<Path> real(List<Path> paths) {
        return paths.stream().map(path -> {
            try {
                return path.toRealPath();
            }
            catch (IOException ex) {
                throw new AssertionError("Missing " + path, ex);
            }
        }).toList();
    }
}
