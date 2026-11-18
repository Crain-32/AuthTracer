package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Decision 0061: library endpoints that hand out secrets or control, when they answer anyone.
 */
class SensitiveEndpointFixtureTests {

    @TempDir
    Path dir;

    @Test
    void actuatorWritesAndTheHeapDump() {
        // /actuator/** is permitAll: what writes is reported, what only reads (env values are masked) isn't.
        assertThat(open(FixtureScans.scan("actuatorcloud"))).contains("POST /actuator/env", "DELETE /actuator/env",
                "POST /actuator/refresh", "POST /actuator/loggers/{name}").doesNotContain("GET /actuator/env",
                        "GET /actuator/features");
        assertThat(messages(FixtureScans.scan("actuatorcloud"), "POST /actuator/refresh")).singleElement()
                .satisfies(message -> assertThat(message).startsWith("Actuator's refresh endpoint (POST"
                        + " /actuator/refresh) answers anyone: it reloads the configuration"));
        // The heap dump falls through to anyRequest().authenticated(), the writes ask for ROLE_OPS.
        assertThat(open(FixtureScans.scan("actuator"))).isEmpty();
    }

    @Test
    void theH2ConsoleOnlyWhenItLetsInOtherHosts() {
        // ignoring() takes it out of the filter chain.
        assertThat(open(FixtureScans.scan("h2remote"))).containsExactlyInAnyOrder("GET /h2-console/**",
                "POST /h2-console/**");
        // permitAll(), but H2 itself refuses other hosts.
        assertThat(open(FixtureScans.scan("servlets"))).isEmpty();
    }

    @Test
    void theConfigServersDecryptAndTheEurekaServersRegistry() {
        assertThat(open(FixtureScans.scan("configserver"))).containsExactly("POST /config/decrypt");
        // Reading the registry tells less than writing it.
        assertThat(open(FixtureScans.scan("eurekaserver"))).containsExactlyInAnyOrder("POST /eureka/**",
                "PUT /eureka/**", "DELETE /eureka/**");
    }

    @Test
    void notWhenAProvidedRequirementGuardsIt() throws IOException {
        Path file = Files.writeString(dir.resolve("authtracer.yaml"), """
                version: 1
                facts:
                  - kind: requirement
                    ingress: "/eureka/**"
                    requirement: "Only the cluster's network reaches the registry"
                """);
        ProvidedFacts facts = ProvidedFacts.load(Optional.of(file), Optional.empty(), "fixture");
        assertThat(open(FixtureScans.scan("eurekaserver", facts))).isEmpty();
    }

    @Test
    void theEnvironmentWithItsValuesUnmasked() {
        ApplicationGraph graph = FixtureScans.scan("actuatorvalues");
        assertThat(open(graph)).contains("GET /actuator/env").noneMatch(endpoint -> endpoint.contains("configprops"));
        assertThat(messages(graph, "GET /actuator/env")).singleElement()
                .satisfies(message -> assertThat(message).contains("show-values=always"));
    }

    private static List<String> open(ApplicationGraph graph) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPEN_SENSITIVE_ENDPOINT)
                .map(finding -> finding.message().substring(finding.message().indexOf('(') + 1,
                        finding.message().indexOf(')')))
                .toList();
    }

    private static List<String> messages(ApplicationGraph graph, String endpoint) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPEN_SENSITIVE_ENDPOINT
                && finding.message().contains("(" + endpoint + ")")).map(Finding::message).toList();
    }
}
