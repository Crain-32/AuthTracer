package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.scan.ArtifactScans.Limits;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What a scan reads from a built Boot jar or war, and the archives it refuses to unpack.
 */
class ArtifactScansTests {

    @TempDir
    Path dir;

    @Test
    void aBootJarIsItsClassesWithTheirConfigurationAndItsLibrariesInTheOrderBootRunsThem() throws IOException {
        Path jar = archive("orders-1.4.0.jar", manifest("orders-app", "1.4.0"), entries(
                "org/springframework/boot/loader/launch/JarLauncher.class", "loader",
                "BOOT-INF/classes/dev/orders/App.class", "app",
                "BOOT-INF/classes/application.yaml", "spring.application.name: orders\n",
                "BOOT-INF/lib/b.jar", "b",
                "BOOT-INF/lib/a.jar", "a",
                "BOOT-INF/classpath.idx", "- \"BOOT-INF/lib/a.jar\"\n- \"BOOT-INF/lib/b.jar\"\n"));

        ScanInput input = scan(jar);

        Path classes = work().resolve("classes");
        assertThat(input.service()).isEqualTo("orders");
        assertThat(input.revision()).isEqualTo("1.4.0");
        assertThat(input.classDirs()).containsExactly(classes);
        assertThat(input.resourceDirs()).containsExactly(classes);
        assertThat(classes.resolve("dev/orders/App.class")).hasContent("app");
        assertThat(input.libraries()).containsExactly(work().resolve("BOOT-INF/lib/a.jar"),
                work().resolve("BOOT-INF/lib/b.jar"));
        // Boot's own launcher isn't the application's.
        assertThat(work().resolve("org")).doesNotExist();
    }

    @Test
    void aWarsRootIsItsWebAppsResourcesAndItsProvidedLibrariesAreLibrariesToo() throws IOException {
        Path war = archive("legacy.war", new Manifest(), entries(
                "WEB-INF/classes/dev/legacy/App.class", "app",
                "WEB-INF/web.xml", "<web-app/>",
                "WEB-INF/lib/servlet-api.jar", "compiled with",
                "WEB-INF/lib-provided/servlet-api.jar", "provided",
                "WEB-INF/lib/nested/ignored.jar", "nested",
                "views/index.jsp", "<html/>"));

        ScanInput input = scan(war);

        Path webapp = work().resolve("webapp");
        assertThat(input.resourceDirs()).containsExactly(work().resolve("classes"), webapp);
        assertThat(webapp.resolve("WEB-INF/web.xml")).exists();
        assertThat(webapp.resolve("views/index.jsp")).exists();
        assertThat(webapp.resolve("WEB-INF/lib")).doesNotExist();
        assertThat(input.libraries()).containsExactly(work().resolve("WEB-INF/lib/servlet-api.jar"),
                work().resolve("WEB-INF/lib-provided/servlet-api.jar"));
        assertThat(input.service()).isEqualTo("legacy");
        assertThat(input.revision()).isEqualTo(ArtifactScans.UNVERSIONED);
    }

    @Test
    void theServiceIsTheManifestsTitleWhenTheConfigurationDoesNotNameItAndTheCommitIsTheRevision() throws IOException {
        Path jar = archive("orders-1.4.0.jar", manifest("orders-app", "1.4.0"), entries(
                "BOOT-INF/classes/git.properties", "git.commit.id.abbrev=abc1234\n",
                "BOOT-INF/classes/META-INF/build-info.properties", "build.version=1.4.0-build\n"));

        ScanInput input = scan(jar);

        assertThat(input.service()).isEqualTo("orders-app");
        assertThat(input.revision()).isEqualTo("abc1234");
    }

    @Test
    void whatTheCallerSaysOverridesWhatTheArtifactRecords() throws IOException {
        Path jar = archive("orders-1.4.0.jar", manifest("orders-app", "1.4.0"), entries(
                "BOOT-INF/classes/application.yaml", "spring.application.name: orders\n"));

        ScanInput input = ArtifactScans.artifact(jar, work(), "billing", "def5678", List.of("dev.billing"),
                Optional.empty(), Optional.empty());

        assertThat(input.service()).isEqualTo("billing");
        assertThat(input.revision()).isEqualTo("def5678");
        assertThat(input.packagePrefixes()).containsExactly("dev.billing");
    }

    @Test
    void anArtifactWithoutAServiceNameIsNamedAfterItsFileWithoutTheVersion() {
        assertThat(ArtifactScans.named(Path.of("employee-service-0.0.1-SNAPSHOT.jar"))).isEqualTo("employee-service");
        assertThat(ArtifactScans.named(Path.of("Orders-2.3.war"))).isEqualTo("orders");
        assertThat(ArtifactScans.named(Path.of("orders.jar"))).isEqualTo("orders");
    }

    @Test
    void aPlainJarIsNotScannableItHasNoLibrariesToResolveTheFrameworkWith() throws IOException {
        Path plain = archive("orders-1.4.0-plain.jar", manifest("orders", "1.4.0"), entries(
                "dev/orders/App.class", "app"));
        Path notAZip = Files.writeString(dir.resolve("broken.jar"), "not a zip");

        assertThat(ArtifactScans.scannable(plain)).isFalse();
        assertThat(ArtifactScans.scannable(notAZip)).isFalse();
        assertThatThrownBy(() -> scan(plain)).isInstanceOf(UsageException.class)
                .hasMessageContaining("neither a Spring Boot jar");
        assertThatThrownBy(() -> scan(notAZip)).isInstanceOf(UsageException.class).hasMessageContaining("isn't a jar");
    }

    @Test
    void aWorkDirectoryGivenWithDotsIsItself() throws IOException {
        Path jar = archive("orders.jar", manifest("orders", "1"), entries(
                "org/springframework/boot/loader/launch/JarLauncher.class", "loader",
                "BOOT-INF/classes/dev/orders/App.class", "app"));

        ScanInput input = ArtifactScans.artifact(jar, dir.resolve("x/../work/."), null, null, List.of(),
                Optional.empty(), Optional.empty());

        assertThat(work().resolve("classes/dev/orders/App.class")).hasContent("app");
        assertThat(input.classDirs()).hasSize(1);
    }

    @Test
    void anEntryThatWouldLandOutsideTheWorkDirectoryIsRefused() throws IOException {
        Path jar = archive("orders.jar", new Manifest(), entries(
                "BOOT-INF/classes/App.class", "app",
                "BOOT-INF/classes/../../../escaped.txt", "escaped"));

        assertThatThrownBy(() -> scan(jar)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside classes/");
        assertThat(dir.resolve("escaped.txt")).doesNotExist();
    }

    @Test
    void anArchiveThatUnpacksToMoreThanTheLimitsIsRefused() throws IOException {
        Path jar = archive("orders.jar", new Manifest(), entries(
                "BOOT-INF/classes/a.txt", "a".repeat(600),
                "BOOT-INF/classes/b.txt", "b".repeat(600)));

        assertThatThrownBy(() -> ArtifactScans.artifact(jar, work(), null, null, List.of(), Optional.empty(),
                Optional.empty(), new Limits(1, Long.MAX_VALUE))).hasMessageContaining("entries");
        assertThatThrownBy(() -> ArtifactScans.artifact(jar, dir.resolve("again"), null, null, List.of(),
                Optional.empty(), Optional.empty(), new Limits(100, 1000)))
                .hasMessageContaining("more than 1000 bytes");
    }

    private ScanInput scan(Path archive) {
        return ArtifactScans.artifact(archive, work(), null, null, List.of(), Optional.empty(), Optional.empty());
    }

    private Path work() {
        return dir.resolve("work");
    }

    private Path archive(String name, Manifest manifest, Map<String, String> entries) throws IOException {
        Path file = dir.resolve(name);
        try (OutputStream out = Files.newOutputStream(file); JarOutputStream jar = new JarOutputStream(out, manifest)) {
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                jar.putNextEntry(new ZipEntry(entry.getKey()));
                jar.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                jar.closeEntry();
            }
        }
        return file;
    }

    private static Manifest manifest(String title, String version) {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.IMPLEMENTATION_TITLE, title);
        manifest.getMainAttributes().put(Attributes.Name.IMPLEMENTATION_VERSION, version);
        return manifest;
    }

    private static Map<String, String> entries(String... namesAndContents) {
        Map<String, String> entries = new LinkedHashMap<>();
        for (int i = 0; i < namesAndContents.length; i += 2) {
            entries.put(namesAndContents[i], namesAndContents[i + 1]);
        }
        return entries;
    }
}
