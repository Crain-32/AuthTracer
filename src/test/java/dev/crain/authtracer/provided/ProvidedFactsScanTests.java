package dev.crain.authtracer.provided;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProvidedFactsScanTests {

    @TempDir
    Path dir;

    @Test
    void aDeclaredCheckBecomesALocationAndIsNoLongerListedAsHandRolled() throws IOException {
        ApplicationGraph graph = FixtureScans.scan("handrolled", facts("""
                version: 1
                facts:
                  - kind: check
                    method: "fixtures.handrolled.LegacyController#secret(long,org.springframework.security.core.Authentication)"
                    requirement: "hasRole('ADMIN')"
                    reason: reviewed by security
                """));

        assertThat(path(graph, "ingress:GET /legacy/{id}")).singleElement().satisfies(id -> {
            AuthorizationLocation location = (AuthorizationLocation) graph.node(id).orElseThrow();
            assertThat(location.mechanism()).isEqualTo("Provided check (LOCAL)");
            assertThat(location.requirement().authorities()).containsExactly("ROLE_ADMIN");
        });
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .extracting(Finding::message).noneMatch(message -> message.contains("#secret"))
                .anySatisfy(message -> assertThat(message).contains("#manual"));
        assertThat(graph.provided()).hasSize(1);
    }

    @Test
    void aProvidedRequirementGuardsMatchingIngressFirst() throws IOException {
        ApplicationGraph graph = FixtureScans.scan("handrolled", facts("""
                version: 1
                facts:
                  - kind: requirement
                    ingress: "GET /legacy/**"
                    requirement: "Only reachable through the admin VPN"
                """));

        assertThat(path(graph, "ingress:GET /legacy/whoami")).first().satisfies(id -> {
            AuthorizationLocation location = (AuthorizationLocation) graph.node(id).orElseThrow();
            assertThat(location.requirement().kind()).isEqualTo(Requirement.Kind.EXPRESSION);
            assertThat(location.requirement().expression()).isEqualTo("Only reachable through the admin VPN");
        });
    }

    @Test
    void aProvidedRequirementInSpelIsReadAsSpringWouldAndACheckWithoutOneIsOpaque() throws IOException {
        ApplicationGraph graph = FixtureScans.scan("handrolled", facts("""
                version: 1
                facts:
                  - kind: requirement
                    ingress: "GET /legacy/**"
                    requirement: "hasRole('ADMIN')"
                  - kind: check
                    method: "fixtures.handrolled.LegacyController#secret(long,org.springframework.security.core.Authentication)"
                """));

        assertThat(path(graph, "ingress:GET /legacy/{id}")).extracting(id -> (AuthorizationLocation) graph.node(id)
                .orElseThrow()).satisfiesExactly(
                        requirement -> assertThat(requirement.requirement().authorities()).containsExactly(
                                "ROLE_ADMIN"),
                        check -> assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.EXPRESSION));
    }

    /**
     * A mistyped field would leave the data unlabelled and every policy on the label unchecked, with nothing said.
     */
    @Test
    void aFactThatMatchesNothingInTheGraphIsReported() throws IOException {
        ApplicationGraph graph = FixtureScans.scan("flows", facts("""
                version: 1
                facts:
                  - kind: sensitive
                    field: fixtures.flows.Source.secret
                    labels: [PII]
                  - kind: sensitive
                    field: fixtures.flows.Source.secert
                    labels: [PII]
                  - kind: check
                    method: "fixtures.flows.Nowhere#nothing()"
                """));

        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith(
                        "LOCAL sensitive fact on field:fixtures.flows.Source.secert matches nothing in the graph"))
                .anySatisfy(message -> assertThat(message).startsWith(
                        "LOCAL check fact on fixtures.flows.Nowhere#nothing() matches nothing in the graph"))
                .noneMatch(message -> message.contains("Source.secret "));
    }

    @Test
    void sensitivityIsInheritedUnlessDeclassified() throws IOException {
        ApplicationGraph graph = FixtureScans.scan("flows", facts("""
                version: 1
                facts:
                  - kind: sensitive
                    field: fixtures.flows.Source.secret
                    labels: [PII]
                  - kind: declassify
                    field: fixtures.flows.View.secretLength
                    reason: a length reveals nothing
                """));

        assertThat(exposure(graph, "passedThrough").labels()).containsExactly("PII");
        Exposure length = exposure(graph, "secretLength");
        assertThat(length.labels()).isEmpty();
        assertThat(length.sources()).containsExactly("flows/field:fixtures.flows.View.secretLength");
    }

    private static Exposure exposure(ApplicationGraph graph, String field) {
        return Exposures.of(graph).stream()
                .filter(exposure -> exposure.endpoint().equals("GET /view") && exposure.field().equals(field))
                .findFirst().orElseThrow();
    }

    private ProvidedFacts facts(String yaml) throws IOException {
        Path file = Files.writeString(dir.resolve("authtracer.yaml"), yaml);
        return ProvidedFacts.load(Optional.of(file), Optional.empty(), "fixture");
    }
}
