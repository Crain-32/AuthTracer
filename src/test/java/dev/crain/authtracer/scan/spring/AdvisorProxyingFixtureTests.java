package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Which auto-proxy creator applies a method-security advisor bean when there is no {@code @EnableMethodSecurity}:
 * Spring Boot's (all of them with AspectJ, only the infrastructure ones without), or none.
 */
class AdvisorProxyingFixtureTests {

    @Test
    void bootWithAspectJAppliesEveryAdvisorBean() {
        ApplicationGraph graph = FixtureScans.scan("bootadvisors");
        assertThat(advisors(graph, "GET /stock")).containsExactly("Advisor guardCount()");
        assertThat(advisors(graph, "POST /stock/reserve")).containsExactly("Advisor guardReserve()");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED);
    }

    @Test
    void bootWithoutAspectJAppliesOnlyTheInfrastructureAdvisors() {
        ApplicationGraph graph = FixtureScans.scanWithout("bootadvisors", "aspectjweaver");
        assertThat(advisors(graph, "GET /stock")).containsExactly("Advisor guardCount()");
        assertThat(advisors(graph, "POST /stock/reserve")).isEmpty();
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).singleElement().asString()
                .contains("guardReserve()", "ROLE_INFRASTRUCTURE", "Spring Boot's auto-proxy creator ignores it");
    }

    @Test
    void withoutMethodSecurityOrAutoProxyingNoAdvisorRuns() {
        ApplicationGraph graph = FixtureScans.scan("plainadvisors");
        assertThat(advisors(graph, "GET /catalog")).isEmpty();
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).singleElement().asString()
                .contains("guardCatalog()", "nothing auto-proxies beans");
    }

    private static List<String> advisors(ApplicationGraph graph, String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .map(AuthorizationLocation::mechanism).filter(mechanism -> mechanism.startsWith("Advisor ")).toList();
    }
}
