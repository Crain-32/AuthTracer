package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.scan.build.BuildClasspath;
import dev.crain.authtracer.scan.build.Builds;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Multi-project Gradle builds, with AuthTracer's own wrapper.
 */
class GradleBuildsTests {

    @TempDir
    Path build;

    @BeforeEach
    void realPath() throws IOException {
        // Gradle prints real paths: /private/var on macOS for /var.
        build = build.toRealPath();
    }

    @Test
    void aSiblingModulesJarIsBuiltBeforeItIsRead() throws IOException {
        multiProject("app", "lib");
        Path app = build.resolve("app");

        BuildClasspath classpath = Builds.resolve(app);

        Path lib = build.resolve("lib/build/libs/lib.jar");
        assertThat(classpath.libraries()).contains(lib);
        assertThat(lib).isRegularFile();
        // Only the project asked for: not lib's classes too.
        assertThat(classpath.classDirs()).allMatch(path -> path.startsWith(app));
    }

    @Test
    void aRootThatIsntAServiceNamesItsProjects() throws IOException {
        multiProject("app", "lib");

        assertThatThrownBy(() -> Builds.resolve(build)).isInstanceOf(UsageException.class)
                .hasMessageContaining("multi-project build").hasMessageContaining("app").hasMessageContaining("lib");
    }

    @Test
    void aRootWithOneProjectScansIt() throws IOException {
        Files.writeString(build.resolve("settings.gradle"), "rootProject.name = 'root'\ninclude 'app'\n");
        javaProject("app", "");
        wrapper();

        assertThat(Builds.resolve(build).classDirs()).isNotEmpty()
                .allMatch(path -> path.startsWith(build.resolve("app")));
    }

    private void multiProject(String app, String lib) throws IOException {
        Files.writeString(build.resolve("settings.gradle"), "rootProject.name = 'root'\ninclude '" + app + "', '"
                + lib + "'\n");
        // A java-library compiles its dependents against its classes: only their runtime needs its jar.
        javaProject(lib, "apply plugin: 'java-library'\n");
        javaProject(app, "dependencies { implementation project(':" + lib + "') }\n");
        wrapper();
    }

    private void javaProject(String name, String dependencies) throws IOException {
        Path dir = Files.createDirectories(build.resolve(name).resolve("src/main/java/" + name));
        Files.writeString(build.resolve(name).resolve("build.gradle"), "plugins { id 'java' }\n" + dependencies);
        Files.writeString(dir.resolve("Thing.java"), "package " + name + ";\n\npublic class Thing {\n}\n");
    }

    /**
     * AuthTracer's own wrapper, so the Gradle distribution is already downloaded.
     */
    private void wrapper() throws IOException {
        Path wrapperDir = Files.createDirectories(build.resolve("gradle/wrapper"));
        for (String file : new String[] {"gradle-wrapper.jar", "gradle-wrapper.properties"}) {
            Files.copy(Path.of("gradle/wrapper", file), wrapperDir.resolve(file));
        }
        Files.copy(Path.of("gradlew"), build.resolve("gradlew"));
        build.resolve("gradlew").toFile().setExecutable(true);
    }
}
