package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-16: a configurer from a library, applied with http.with(..) or in META-INF/spring.factories, isn't read, so
 * it is an OPAQUE_CONFIG finding naming it rather than nothing.
 */
class LibraryDslFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("librarydsl");

    @Test
    void aLibraryConfigurerAppliedWithWithIsNamed() {
        assertThat(opaque()).filteredOn(finding -> finding.message().startsWith("http.with(..) applies"
                + " fixtures.securitylib.TenantSecurityDsl, a configurer from a library AuthTracer doesn't read"))
                .extracting(finding -> finding.location().method())
                .anySatisfy(method -> assertThat(method).startsWith("tenants("))
                .anySatisfy(method -> assertThat(method).startsWith("app("));
    }

    @Test
    void oneInSpringFactoriesIsNamedToo() {
        assertThat(opaque()).anySatisfy(finding -> {
            assertThat(finding.message()).startsWith("META-INF/spring.factories applies"
                    + " fixtures.securitylib.AuditSecurityDsl");
            assertThat(finding.location().className()).isEqualTo("fixtures.securitylib.AuditSecurityDsl");
        });
    }

    @Test
    void theChainsOwnRulesStillApply() {
        assertThat(rule(graph, "GET /tenants/acme").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    private List<Finding> opaque() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG).toList();
    }
}
