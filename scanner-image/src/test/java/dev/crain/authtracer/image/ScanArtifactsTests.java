package dev.crain.authtracer.image;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.scan.ProjectScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Which artifacts the image scans, where their graphs go, and the exit code it ends with. The artifacts are Boot jars
 * with configuration and no classes: what a scan finds in real classes is the scanner's to test.
 */
class ScanArtifactsTests {

    @TempDir
    Path dir;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    @Test
    void eachBootJarsGraphIsWrittenUnderItsServicesNameAndAPlainJarIsPassedOver() throws IOException {
        bootJar("orders-1.4.0.jar", "orders");
        bootJar("billing-2.0.jar", "billing");
        jar("orders-1.4.0-plain.jar", "dev/orders/App.class", "app");

        assertThat(run(Map.of("AUTHTRACER_REVISION", "abc1234"))).isEqualTo(ScanArtifacts.OK);

        assertThat(graph("orders").revision()).isEqualTo("abc1234");
        assertThat(graph("billing").service()).isEqualTo("billing");
        try (Stream<Path> files = Files.list(out())) {
            assertThat(files).map(file -> file.getFileName().toString())
                    .containsExactlyInAnyOrder("orders.json", "billing.json");
        }
        assertThat(err()).contains("passing over orders-1.4.0-plain.jar");
        assertThat(out.toString()).contains("orders at abc1234, from orders-1.4.0.jar");
        // What was unpacked to scan goes once it's scanned.
        try (Stream<Path> files = Files.list(work())) {
            assertThat(files).isEmpty();
        }
    }

    @Test
    void inAGitHubWorkflowTheRevisionIsTheCommitTheWorkflowRunsFor() throws IOException {
        bootJar("orders-1.4.0.jar", "orders");

        run(Map.of("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567"));

        assertThat(graph("orders").revision()).isEqualTo("0123456");
    }

    @Test
    void anArtifactThatCannotBeScannedFailsTheRunButNotTheOthers() throws IOException {
        bootJar("billing-2.0.jar", "billing");
        jar("orders.jar", "BOOT-INF/classes/../../../escaped.txt", "escaped");

        assertThat(run(Map.of())).isEqualTo(ScanArtifacts.ERROR);

        assertThat(out().resolve("billing.json")).exists();
        assertThat(err()).contains("can't scan orders.jar").contains("outside classes/");
    }

    @Test
    void twoArtifactsOfOneServiceAreNotBothWrittenToItsGraph() throws IOException {
        bootJar("orders-1.4.0.jar", "orders");
        bootJar("orders-1.5.0.jar", "orders");

        assertThat(run(Map.of())).isEqualTo(ScanArtifacts.ERROR);

        assertThat(out.toString()).contains("from orders-1.4.0.jar").doesNotContain("orders-1.5.0.jar");
        assertThat(err()).contains("can't scan orders-1.5.0.jar: it's orders too, which orders-1.4.0.jar already is");
    }

    @Test
    void nothingToScanIsAMistakeInHowTheImageIsRun() throws IOException {
        jar("orders-1.4.0-plain.jar", "dev/orders/App.class", "app");

        assertThat(run(Map.of())).isEqualTo(ScanArtifacts.USAGE);

        assertThat(err()).contains("there's no Spring Boot jar or war in").contains("only orders-1.4.0-plain.jar");
    }

    @Test
    void oneServiceNameForSeveralArtifactsIsAMistake() throws IOException {
        bootJar("orders-1.4.0.jar", "orders");
        bootJar("billing-2.0.jar", "billing");

        assertThat(run(Map.of("AUTHTRACER_SERVICE", "orders"))).isEqualTo(ScanArtifacts.USAGE);

        assertThat(err()).contains("AUTHTRACER_SERVICE names one service");
        assertThat(out()).isEmptyDirectory();
    }

    @Test
    void aFactsFileTheEnvironmentNamesMustBeThere() throws IOException {
        bootJar("orders-1.4.0.jar", "orders");

        assertThat(run(Map.of("AUTHTRACER_ORG_FACTS", dir.resolve("org.yaml").toString())))
                .isEqualTo(ScanArtifacts.USAGE);

        assertThat(err()).contains("AUTHTRACER_ORG_FACTS names");
    }

    @Test
    void aServicesNameCannotWriteOutsideTheOutputDirectory() {
        assertThat(ScanArtifacts.fileName("../../etc/cron.d/x")).isEqualTo("_._.._etc_cron.d_x");
        assertThat(ScanArtifacts.fileName("orders")).isEqualTo("orders");
        assertThat(ScanArtifacts.fileName(".hidden")).isEqualTo("_hidden");
    }

    private int run(Map<String, String> settings) throws IOException {
        Files.createDirectories(out());
        Map<String, String> env = new HashMap<>(settings);
        env.put("AUTHTRACER_IN", in().toString());
        env.put("AUTHTRACER_OUT", out().toString());
        env.put("AUTHTRACER_WORK", work().toString());
        return ScanArtifacts.run(env, ProjectScans.defaultScanner(),
                new PrintStream(out, true, StandardCharsets.UTF_8), new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private ApplicationGraph graph(String service) {
        return GraphJson.read(out().resolve(service + ".json"));
    }

    private String err() {
        return err.toString(StandardCharsets.UTF_8);
    }

    private Path in() {
        return dir.resolve("in");
    }

    private Path out() {
        return dir.resolve("out");
    }

    private Path work() {
        return dir.resolve("work");
    }

    private void bootJar(String name, String service) throws IOException {
        jar(name, "BOOT-INF/classes/application.yaml", "spring.application.name: " + service + "\n");
    }

    private void jar(String name, String entry, String content) throws IOException {
        Files.createDirectories(in());
        try (OutputStream file = Files.newOutputStream(in().resolve(name));
                JarOutputStream jar = new JarOutputStream(file)) {
            jar.putNextEntry(new ZipEntry(entry));
            jar.write(content.getBytes(StandardCharsets.UTF_8));
            jar.closeEntry();
        }
    }
}
