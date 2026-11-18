package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Handlers that share a path but not their params are separate endpoints.
 */
class MappingParamsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("mappingparams");

    @Test
    void eachParamsVariantIsItsOwnEndpoint() {
        String delegation = "ingress:GET /user/messages?use_case=delegation";
        String impersonation = "ingress:GET /user/messages?use_case=impersonation";
        assertThat(graph.nodes()).filteredOn(Ingress.class::isInstance).map(node -> ((Ingress) node).id())
                .contains(delegation, impersonation);
        // The route stays the path, which the rules and the linker match.
        assertThat(((Ingress) graph.node(delegation).orElseThrow()).route()).isEqualTo("/user/messages");
        assertThat(path(graph, delegation).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast))
                .singleElement().satisfies(check -> assertThat(check.requirement().authorities())
                        .containsExactly("SCOPE_delegate"));
    }
}
