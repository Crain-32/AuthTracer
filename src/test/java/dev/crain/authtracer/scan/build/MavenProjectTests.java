package dev.crain.authtracer.scan.build;

import static dev.crain.authtracer.scan.build.GradleProjectTests.script;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * Maven projects, built with a stand-in {@code mvnw} that does what Maven does for the command AuthTracer gives it:
 * records the command, compiles into {@code target/classes} and writes the runtime classpath where
 * {@code -Dmdep.outputFile} says. Maven itself isn't run.
 * <p>
 * Stand-in build wrappers and git hooks here are POSIX shell scripts.
 */
@DisabledOnOs(OS.WINDOWS)
class MavenProjectTests {

    /**
     * Records its arguments and directory next to itself, then builds.
     */
    private static final String MAVEN = """
            #!/bin/sh
            echo "$@" > "$(dirname "$0")/mvnw.args"
            pwd -P > "$(dirname "$0")/mvnw.dir"
            mkdir -p target/classes
            for arg in "$@"; do
              case "$arg" in
                -Dmdep.outputFile=*) printf '%s' 'CLASSPATH' > "${arg#-Dmdep.outputFile=}" ;;
              esac
            done
            """;

    @TempDir
    Path project;

    @Test
    void aProjectIsCompiledWithItsWrapperAndItsRuntimeJarsAreTheLibraries() throws IOException {
        Files.writeString(project.resolve("pom.xml"), "<project/>");
        Path core = project.resolve("repository/core.jar");
        Path web = project.resolve("repository/web.jar");
        Path sibling = project.resolve("../sibling/target/classes");
        maven(project.resolve("mvnw"), String.join(File.pathSeparator, core.toString(), sibling.toString(),
                web.toString()) + "\n");

        BuildClasspath classpath = Builds.resolve(project);

        String args = Files.readString(project.resolve("mvnw.args")).trim();
        assertThat(args).startsWith("-q -B -DskipTests compile dependency:build-classpath -Dmdep.includeScope=runtime"
                + " -Dmdep.outputFile=");
        assertThat(classpath.classDirs()).containsExactly(project.resolve("target/classes"));
        assertThat(classpath.resourceDirs()).containsExactly(project.resolve("target/classes"));
        // Jars only: a sibling module's classes directory is the scan's to leave out.
        assertThat(classpath.libraries()).containsExactly(core, web);
        // The classpath file was a temporary one.
        assertThat(Path.of(args.substring(args.indexOf("-Dmdep.outputFile=") + "-Dmdep.outputFile=".length())))
                .doesNotExist();
    }

    @Test
    void aWebApplicationsWebappIsAResourceDirectory() throws IOException {
        Files.writeString(project.resolve("pom.xml"), "<project/>");
        Files.createDirectories(project.resolve("src/main/webapp/WEB-INF"));
        maven(project.resolve("mvnw"), "");

        BuildClasspath classpath = Builds.resolve(project);

        assertThat(classpath.resourceDirs()).containsExactly(project.resolve("target/classes"),
                project.resolve("src/main/webapp"));
        assertThat(classpath.libraries()).isEmpty();
    }

    @Test
    void aModuleIsBuiltWithItsBuildsWrapperInItsOwnDirectory() throws IOException {
        Files.writeString(project.resolve("pom.xml"), "<project/>");
        maven(project.resolve("mvnw"), "");
        Path module = Files.createDirectories(project.resolve("orders"));
        Files.writeString(module.resolve("pom.xml"), "<project/>");

        BuildClasspath classpath = Builds.resolve(module);

        assertThat(Files.readString(project.resolve("mvnw.dir")).trim()).isEqualTo(module.toRealPath().toString());
        assertThat(classpath.classDirs()).containsExactly(module.resolve("target/classes"));
    }

    @Test
    void aWrapperOutsideTheBuildIsNotItsOwn() throws IOException {
        maven(project.resolve("mvnw"), "");
        // Between the wrapper and the project, a directory that isn't part of a Maven build.
        Path module = Files.createDirectories(project.resolve("services/orders"));
        Files.writeString(module.resolve("pom.xml"), "<project/>");

        // Maven itself (mvn) is run instead: on a machine without it, the scan can't start it.
        assertThatThrownBy(() -> Builds.resolve(module)).isInstanceOf(RuntimeException.class);
        assertThat(project.resolve("mvnw.args")).doesNotExist();
    }

    @Test
    void aBuildThatFailsReportsMavensOutput() throws IOException {
        Files.writeString(project.resolve("pom.xml"), "<project/>");
        script(project.resolve("mvnw"), """
                #!/bin/sh
                echo "[ERROR] COMPILATION ERROR : App.java:[3,1] class, interface, enum, or record expected"
                exit 1
                """);

        assertThatThrownBy(() -> Builds.resolve(project)).isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("Maven failed for " + project)
                .hasMessageContaining("[ERROR] COMPILATION ERROR");
    }

    @Test
    void aBuildWithoutClassesIsNoService() throws IOException {
        // An aggregator (packaging pom) compiles nothing of its own.
        Files.writeString(project.resolve("pom.xml"), "<project><packaging>pom</packaging></project>");
        script(project.resolve("mvnw"), "#!/bin/sh\necho '[INFO] BUILD SUCCESS'\n");

        assertThatThrownBy(() -> Builds.resolve(project)).isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("Maven built no target/classes in " + project)
                .hasMessageContaining("BUILD SUCCESS");
    }

    private static void maven(Path wrapper, String classpath) throws IOException {
        script(wrapper, MAVEN.replace("'CLASSPATH'", "'" + classpath + "'"));
    }
}
