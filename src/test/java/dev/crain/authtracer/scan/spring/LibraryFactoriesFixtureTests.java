package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * HTTP-16: Spring Security applies every AbstractHttpConfigurer a library jar's META-INF/spring.factories names to
 * every HttpSecurity; one AuthTracer doesn't read is an OPAQUE_CONFIG finding naming it and the jar.
 */
class LibraryFactoriesFixtureTests {

    @TempDir
    Path jars;

    @Test
    void aConfigurerALibraryJarListsIsNamedWithTheJar() throws IOException {
        Path jar = jar("audit-starter.jar", "org.springframework.security.config.annotation.web.configurers"
                + ".AbstractHttpConfigurer=\\\n  fixtures.securitylib.AuditSecurityDsl\n");
        ApplicationGraph graph = FixtureScans.scanWithLibraries("libraryfactories", List.of(jar));
        assertThat(opaque(graph)).anySatisfy(finding -> {
            assertThat(finding.message()).startsWith("The META-INF/spring.factories of audit-starter.jar applies"
                    + " fixtures.securitylib.AuditSecurityDsl, a configurer from a library AuthTracer doesn't read");
            assertThat(finding.location().className()).isEqualTo("fixtures.securitylib.AuditSecurityDsl");
        });
    }

    @Test
    void aJarWithoutConfigurersAndBootsGrpcCsrfConfigurerAddNothing() throws IOException {
        Path jar = jar("other-starter.jar", "org.springframework.boot.autoconfigure.AutoConfiguration=x.Y\n");
        // The fixtures' classpath has spring-boot-grpc-server, whose configurer only turns CSRF off for gRPC.
        assertThat(opaque(FixtureScans.scanWithLibraries("libraryfactories", List.of(jar)))).isEmpty();
    }

    private Path jar(String name, String factories) throws IOException {
        Path jar = jars.resolve(name);
        try (OutputStream out = Files.newOutputStream(jar); ZipOutputStream zip = new ZipOutputStream(out)) {
            zip.putNextEntry(new ZipEntry("META-INF/spring.factories"));
            zip.write(factories.getBytes(StandardCharsets.ISO_8859_1));
            zip.closeEntry();
        }
        return jar;
    }

    private static List<Finding> opaque(ApplicationGraph graph) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG).toList();
    }
}
