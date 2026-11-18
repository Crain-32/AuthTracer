package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0036: Spring Security's XML namespace configuration.
 */
class XmlConfigFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("xmlconfig");

    @Test
    void httpChainsAndTheirInterceptUrls() {
        assertThat(rule(graph, "GET /api/admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(rule(graph, "GET /api/items").requirement().authorities()).containsExactly("SCOPE_read");
        // The /api/** chain has no rule for POST: denied by default.
        assertThat(rule(graph, "POST /api/items").requirement()).isEqualTo(Requirement.denyAll());
        assertThat(rule(graph, "GET /login").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /home").requirement().kind()).isEqualTo(Requirement.Kind.AUTHENTICATED);
        assertThat(rule(graph, "GET /home").target().className()).isEqualTo("WEB-INF/spring/security.xml");
        assertThat(rule(graph, "GET /home").target().line()).isEqualTo(17);
    }

    @Test
    void securityNoneSkipsTheChains() {
        assertThat(rule(graph, "GET /css/site.css").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }

    @Test
    void methodSecurityEnabledInXml() {
        assertThat(path(graph, "ingress:GET /api/items"))
                .contains("location:METHOD:fixtures.xmlconfig.Inventory#list():@PreAuthorize");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("@Secured"));
    }

    @Test
    void anInterfacesChecksRunOnTheXmlBeanImplementingIt() {
        assertThat(path(graph, "ingress:GET /catalog"))
                .anySatisfy(step -> assertThat(step).contains("browse()").endsWith("@PreAuthorize"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).noneSatisfy(message -> assertThat(message).contains("browse"));
    }

    @Test
    void theLoginElementsAreTheAuthoritySource() {
        assertThat(graph.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.JWT_CLAIMS);
        assertThat(graph.authoritySource().detail()).contains("Form login");
    }
}
