package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A body in a library's container is its elements: a page's, a map's values, a HATEOAS model's content.
 */
class ContainersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("containers");

    @Test
    void aLibrarysContainerIsManyOfItsElements() {
        for (String route : List.of("/page", "/map", "/models", "/list")) {
            assertThat(response(route)).as(route).isEqualTo(new Payload("fixtures.containers.Account", true));
        }
        assertThat(response("/model")).isEqualTo(new Payload("fixtures.containers.Account", false));
        assertThat(graph.node("field:fixtures.containers.Account.iban")).isPresent();
    }

    @Test
    void aLibraryTypeItCantFollowIsReported() {
        assertThat(response("/entry")).isEqualTo(new Payload("java.util.Map$Entry", false));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).containsExactly("On GET /entry: the response is a"
                        + " java.util.Map$Entry<java.lang.String, fixtures.containers.Account>, a library type"
                        + " AuthTracer doesn't know how Jackson writes: the fields of the application's types in it"
                        + " aren't in the graph");
    }

    /**
     * Found by conformanceTest: the class's pointcut matches every method, and the CGLIB proxy intercepts a
     * package-private handler, so the class's @PreAuthorize guards it.
     */
    @Test
    void aClassLevelCheckGuardsItsPackagePrivateHandlers() {
        assertThat(FixtureScans.path(graph, "ingress:GET /page")).contains(
                "location:METHOD:fixtures.containers.AccountsController#page():@PreAuthorize");
    }

    private Payload response(String route) {
        return ((Ingress) graph.node("ingress:GET " + route).orElseThrow()).response();
    }
}
