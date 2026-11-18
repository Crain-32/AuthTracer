package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Spring Framework 7.0.9's RouterFunctionBuilder#build wraps every route it has in its filters (before(..) is one),
 * and RouterFunction#filter every route of the function: they run before the handler.
 */
class FunctionalFiltersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("functionalfilters");

    private List<String> authorities(String ingressId) {
        return FixtureScans.path(graph, ingressId).stream().flatMap(id -> graph.node(id).stream())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .flatMap(location -> location.requirement().authorities().stream()).toList();
    }

    @Test
    void aBuildersFilterRunsBeforeEveryRouteItBuilds() {
        // before(..) is added between the two routes, and filters both.
        assertThat(authorities("ingress:GET /reports")).contains("ROLE_AUDITOR");
        assertThat(authorities("ingress:GET /reports/latest")).contains("ROLE_AUDITOR");
    }

    @Test
    void aFilterClassIsWalkedBeforeTheHandler() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK)
                .anySatisfy(finding -> assertThat(finding.location().className())
                        .isEqualTo("fixtures.functionalfilters.TellersOnly"));
    }

    @Test
    void aFilterAuthTracerCantFollowIsAFinding() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("runs POST /imports through a filter AuthTracer"
                        + " can't follow"));
    }
}
