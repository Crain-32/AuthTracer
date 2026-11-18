package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A servlet container registers a war's @WebServlet and @WebFilter classes itself unless its web.xml is
 * metadata-complete (Tomcat 11.0.24's ContextConfig#webConfig); Boot 4.1.1's embedded server only with
 * @ServletComponentScan ("Scanning is only performed when using an embedded web server").
 */
class WarServletsFixtureTests {

    private static List<String> ingresses(ApplicationGraph graph) {
        return graph.nodes(Ingress.class).stream().map(Ingress::id).toList();
    }

    @Test
    void aBootWarsServletsAndFiltersMayBeRegistered() {
        ApplicationGraph graph = FixtureScans.scan("bootwar");
        assertThat(ingresses(graph)).contains("ingress:GET /legacy/report");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("The @WebServlet"
                        + " fixtures.bootwar.LegacyReportServlet is registered by the servlet container"))
                .anySatisfy(message -> assertThat(message).startsWith("The @WebFilter fixtures.bootwar.AuditFilter"));
    }

    @Test
    void aWarWithoutBootHasItsServletsRegistered() {
        ApplicationGraph graph = FixtureScans.scan("plainwar");
        assertThat(ingresses(graph)).contains("ingress:GET /status");
        assertThat(graph.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("@WebServlet"));
    }

    @Test
    void aMetadataCompleteWebXmlHasNone() {
        assertThat(ingresses(FixtureScans.scan("completewar"))).doesNotContain("ingress:GET /status");
    }
}
