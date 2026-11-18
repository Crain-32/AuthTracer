package dev.crain.authtracer.scan;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import org.junit.jupiter.api.Test;

/**
 * Decision 0080 for the call walk's depth: past it, the path shows what wasn't read instead of ending quietly.
 */
class DeepCallsFixtureTests {

    private static final String CHECK = "location:METHOD:fixtures.deepcalls.Vault#secret():@PreAuthorize";

    private final ApplicationGraph graph = FixtureScans.scan("deepcalls");

    @Test
    void aCheckWithinTheWalksDepthIsOnThePath() {
        assertThat(path(graph, "ingress:GET /shallow")).contains(CHECK);
        assertThat(graph.findings()).noneMatch(finding -> finding.message().startsWith("On GET /shallow"));
    }

    @Test
    void aPathDeeperThanTheWalkFollowsEndsInAnOpaqueStepAndAFinding() {
        assertThat(path(graph, "ingress:GET /deep")).doesNotContain(CHECK)
                .last().satisfies(last -> assertThat(last).startsWith("opaque:fixtures.deepcalls.Layers#s"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH)
                .singleElement().satisfies(finding -> assertThat(finding.message())
                        .startsWith("On GET /deep: the call path is more than 40 calls deep at fixtures.deepcalls"
                                + ".Layers#s"));
    }
}
