package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class ProxiesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("proxies");

    @Test
    void aCollectionPassedToProxyHasItsElementsProxied() {
        assertThat(path(graph, "ingress:GET /customers"))
                .contains("location:FIELD:fixtures.proxies.Customer#getTaxId():@PreAuthorize");
    }

    @Test
    void classLevelAuthorizeReturnObjectProxiesEveryResult() {
        assertThat(path(graph, "ingress:GET /invoices/latest"))
                .contains("location:FIELD:fixtures.proxies.Invoice#getTotal():@PreAuthorize");
    }

    @Test
    void skippingValueTypesIsNotAFinding() {
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
    }

    @Test
    void aCustomTargetVisitorIsReported() {
        ApplicationGraph visitors = FixtureScans.scan("visitors");
        assertThat(visitors.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement().asString().contains("skipBadges", "TargetVisitor");
    }
}
