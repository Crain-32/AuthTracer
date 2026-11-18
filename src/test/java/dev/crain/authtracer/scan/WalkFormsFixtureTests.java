package dev.crain.authtracer.scan;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Finding;
import org.junit.jupiter.api.Test;

/**
 * Where the call walk goes: through a bridge, to the beans a call may run, and to the listeners of an event.
 */
class WalkFormsFixtureTests {

    private static final String CHECK = "location:METHOD:fixtures.walkforms.";
    private static final String RULE = "location:HTTP_REQUEST:fixtures.walkforms.WalkFormsApp#api("
            + "org.springframework.security.config.annotation.web.builders.HttpSecurity):0:anyRequest";

    private final ApplicationGraph graph = FixtureScans.scan("walkforms");

    @Test
    void aCheckAnotherCallReachesOnEveryWayIsOnEveryWay() {
        Edge find = graph.path("ingress:GET /docs/{id}").stream()
                .filter(edge -> edge.to().equals(CHECK + "Docs#find(long):@PreAuthorize")).findFirst().orElseThrow();
        assertThat(find.conditional()).isFalse();
        assertThat(requirement("GET /docs/{id}")).isEqualTo("ROLE_READER");
        assertThat(findings("GET /docs/{id}")).isEmpty();
    }

    @Test
    void pastThirtyTwoWaysTheAlternativesCollapseToWhatTheyShare() {
        // 64 ways, each through one check of every pair: none of the checks is on all of them, so none is asked.
        assertThat(graph.path("ingress:POST /chosen")).filteredOn(edge -> edge.to().contains("Choices#"))
                .hasSize(12).allMatch(Edge::conditional);
        assertThat(requirement("POST /chosen")).doesNotContain("ROLE_LEFT", "ROLE_RIGHT");
    }

    @Test
    void aBridgeIsWalkedThroughToTheMethodTheClassInheritsOrOverrides() {
        assertThat(path(graph, "ingress:GET /found/{id}")).containsExactly(RULE,
                CHECK + "BaseFinder#find(long):@PreAuthorize");
        // The abstract base's bridge calls a method only the bean implements.
        assertThat(path(graph, "ingress:GET /looked-up/{id}")).containsExactly(RULE,
                CHECK + "CachedLookup#lookup(long):@PreAuthorize");
        assertThat(findings("GET /looked-up/{id}")).isEmpty();
    }

    @Test
    void anAbstractClassRunsForNoBean() {
        // Archive's own store isn't a way without a check: no object is only an Archive.
        assertThat(requirement("POST /archive/{id}")).contains("ROLE_COLD", "ROLE_HOT").doesNotContain(" and ");
        assertThat(findings("POST /archive/{id}")).isEmpty();
    }

    @Test
    void beansWithoutChecksAreNoAlternatives() {
        assertThat(path(graph, "ingress:GET /formatted/{id}")).containsExactly(RULE);
        assertThat(findings("GET /formatted/{id}")).isEmpty();
    }

    @Test
    void aRecordsGeneratedToStringRunsNoApplicationCode() {
        assertThat(path(graph, "ingress:GET /described/{id}")).containsExactly(RULE);
        assertThat(findings("GET /described/{id}")).isEmpty();
    }

    @Test
    void anEventRunsTheListenersOfItsInterfacesAndOfTheClassesTheyName() {
        assertThat(path(graph, "ingress:POST /read/{id}")).containsExactlyInAnyOrder(RULE,
                CHECK + "Audit#notice():@PreAuthorize", CHECK + "Audit#domain():@PreAuthorize");
    }

    @Test
    void anApplicationListenerRunsForItsEvent() {
        assertThat(path(graph, "ingress:POST /deleted/{id}")).containsExactly(RULE,
                CHECK + "Audit#deletion():@PreAuthorize");
    }

    @Test
    void aConstantEventRunsTheListenersOfItsType() {
        assertThat(path(graph, "ingress:POST /refreshed")).containsExactly(RULE, CHECK + "Audit#text():@PreAuthorize");
    }

    @Test
    void anEventPublishedAsAnObjectRunsNoListenerTheScanCanName() {
        assertThat(path(graph, "ingress:POST /anything")).containsExactly(RULE);
    }

    private String requirement(String endpoint) {
        return Exposures.of(graph).stream()
                .filter(exposure -> exposure.endpoint().equals(endpoint) && exposure.field().isEmpty())
                .findFirst().orElseThrow().requirement();
    }

    private List<String> findings(String endpoint) {
        return graph.findings().stream().map(Finding::message).filter(message -> message.contains(endpoint)).toList();
    }
}
