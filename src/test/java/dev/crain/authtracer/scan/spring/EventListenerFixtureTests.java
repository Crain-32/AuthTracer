package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * {@code publishEvent(..)} reaches the listeners of the event's type, on the publisher's path.
 */
class EventListenerFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("events");

    @Test
    void listenersChecksAndCallsAreOnThePublishersPath() {
        List<Node> nodes = path(graph, "ingress:POST /orders/{id}").stream().map(id -> graph.node(id).orElseThrow())
                .toList();
        assertThat(nodes).filteredOn(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filteredOn(check -> check.mechanism().equals("@PreAuthorize")).singleElement()
                .satisfies(check -> assertThat(check.requirement().authorities()).containsExactly("ROLE_SALES"));
        // @TransactionalEventListener runs after the commit, on the same thread.
        assertThat(nodes).filteredOn(Egress.class::isInstance).map(Egress.class::cast).extracting(Egress::uriTemplate)
                .containsExactly("/shipments/{id}");
    }
}
