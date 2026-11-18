package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Opaque;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * HTTP-17 (decision 0070): servlet filters on the request path, in the order Spring runs them.
 */
class FiltersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("filters");

    @TempDir
    Path dir;

    @Test
    void aChainsFiltersRunAroundItsAuthorizationFilterAndBootsFilterBeansAroundTheChain() {
        assertThat(steps(graph, "ingress:GET /api/orders")).containsExactly("egress GET /tenants/{host}",
                "egress POST /keys/verify", "check authorizeHttpRequests", "egress POST /events?",
                "egress GET /maintenance");
    }

    @Test
    void aFilterBeanIsOnEveryRequestAndAChainsFiltersOnTheChainsOnly() {
        assertThat(steps(graph, "ingress:GET /home")).containsExactly("egress GET /tenants/{host}",
                "check authorizeHttpRequests", "egress GET /maintenance");
    }

    @Test
    void handRolledChecksInFiltersAreFound() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("fixtures.filters.AuditFilter#doFilterInternal", "Authentication.getAuthorities()",
                                "sendError(403)"))
                .anySatisfy(message -> assertThat(message).contains("fixtures.filters.LegacyFilter#doFilter",
                        "HttpServletRequest.isUserInRole()"));
    }

    @Test
    void aReviewedFilterCheckIsALocationOnTheRequestsItCovers() throws IOException {
        ApplicationGraph reviewed = FixtureScans.scan("filters", facts("""
                version: 1
                facts:
                  - kind: check
                    method: "fixtures.filters.LegacyFilter#doFilter(jakarta.servlet.ServletRequest,\
                jakarta.servlet.ServletResponse,jakarta.servlet.FilterChain)"
                    requirement: "hasRole('LEGACY')"
                """));
        assertThat(steps(reviewed, "ingress:GET /legacy/report")).containsExactly("egress GET /tenants/{host}",
                "check authorizeHttpRequests", "check Provided check (LOCAL)", "egress GET /maintenance");
        assertThat(steps(reviewed, "ingress:GET /home")).doesNotContain("check Provided check (LOCAL)");
        assertThat(reviewed.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .extracting(Finding::message).noneMatch(message -> message.contains("LegacyFilter"));
    }

    /**
     * Each step on the Ingress's path, as {@code check <mechanism>}, {@code egress <method> <uri>} or
     * {@code opaque <reason>}, with {@code ?} after one only some requests reach.
     */
    static List<String> steps(ApplicationGraph graph, String ingress) {
        return graph.path(ingress).stream().map(edge -> step(graph.node(edge.to()).orElseThrow())
                + (edge.conditional() ? "?" : "")).toList();
    }

    private static String step(Node node) {
        return switch (node) {
            case AuthorizationLocation location -> "check " + location.mechanism();
            case Egress egress -> "egress " + egress.httpMethod() + " " + egress.uriTemplate();
            case Opaque opaque -> "opaque " + opaque.reason();
            default -> node.id();
        };
    }

    private ProvidedFacts facts(String yaml) throws IOException {
        Path file = Files.writeString(dir.resolve("authtracer.yaml"), yaml);
        return ProvidedFacts.load(Optional.of(file), Optional.empty(), "fixture");
    }
}
