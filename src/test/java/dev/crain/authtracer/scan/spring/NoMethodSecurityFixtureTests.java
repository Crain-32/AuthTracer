package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class NoMethodSecurityFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("nosecurity");

    @Test
    void annotationWithoutEnableMethodSecurityIsNoAuthorization() {
        assertThat(graph.nodes(AuthorizationLocation.class)).isEmpty();
        assertThat(path(graph, "ingress:GET /reports")).isEmpty();
        assertThat(graph.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.NOT_ENFORCED);
            assertThat(finding.message()).contains("ReportService#report").contains("no @EnableMethodSecurity");
        });
    }
}
