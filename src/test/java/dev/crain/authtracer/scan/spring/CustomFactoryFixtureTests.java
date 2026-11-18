package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * ROLE-04: an AuthorizationManagerFactory of the application's own builds the DSL's rules its way; they are shown as
 * the default factory builds them, and reported.
 */
class CustomFactoryFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("customfactory");

    @Test
    void aCustomFactoryIsReportedAndItsRulesShownAsTheDefaultBuildsThem() {
        assertThat(rule(graph, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("CustomFactoryConfig#authorizationManagerFactory() is a custom"
                                + " fixtures.customfactory.TenantAuthorizationManagerFactory"));
    }
}
