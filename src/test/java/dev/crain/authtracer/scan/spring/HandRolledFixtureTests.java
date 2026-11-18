package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Opaque;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class HandRolledFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("handrolled");

    @Test
    void handRolledChecksAreListedButAreNotLocations() {
        assertThat(graph.nodes(AuthorizationLocation.class)).isEmpty();
        assertThat(messages(Finding.Kind.UNRECOGNIZED_CHECK)).satisfiesExactlyInAnyOrder(
                message -> assertThat(message).contains("LegacyController#secret")
                        .contains("Authentication.getAuthorities()").contains("throw AccessDeniedException"),
                message -> assertThat(message).contains("LegacyController#manual")
                        .contains("HttpServletRequest.isUserInRole()").contains("ResponseEntity.status(FORBIDDEN)"),
                // The principal Spring hands in, read directly.
                message -> assertThat(message).contains("LegacyController#owned")
                        .contains("UserDetails.getUsername()"));
    }

    @Test
    void readingTheCallerWithoutDenyingIsNotACheck() {
        assertThat(messages(Finding.Kind.UNRECOGNIZED_CHECK)).noneMatch(message -> message.contains("whoami"));
    }

    @Test
    void reflectionIsAnOpaqueStep() {
        assertThat(path(graph, "ingress:GET /legacy/dynamic")).singleElement()
                .satisfies(id -> assertThat(graph.node(id)).get().isInstanceOf(Opaque.class));
        assertThat(messages(Finding.Kind.OPAQUE_CALLPATH)).singleElement()
                .satisfies(message -> assertThat(message).contains("Method.invoke").contains("GET /legacy/dynamic"));
    }

    private List<String> messages(Finding.Kind kind) {
        return graph.findings().stream().filter(finding -> finding.kind() == kind).map(Finding::message).toList();
    }
}
