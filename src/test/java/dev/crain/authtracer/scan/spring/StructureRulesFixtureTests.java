package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Decision 0120: an authorization library AuthTracer doesn't know, described by its shape in authtracer.yaml.
 */
class StructureRulesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("customlibrary");

    @Test
    void anAnnotationRulesCheckIsTheMethodsWithItsAttributeFilledIn() {
        assertThat(checks("ingress:GET /orders")).singleElement().satisfies(check -> {
            assertThat(check.mechanism()).isEqualTo("Rule @RequiresPermission (LOCAL)");
            assertThat(check.proxied()).isTrue();
            assertThat(check.requirement().authorities()).containsExactly("PERM_orders.read");
        });
    }

    @Test
    void anArrayAttributeAsksForAnyOfItsValues() {
        assertThat(checks("ingress:GET /reports")).singleElement().satisfies(check -> {
            assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.OR);
            assertThat(check.requirement().operands()).flatExtracting(Requirement::authorities)
                    .containsExactlyInAnyOrder("PERM_reports.read", "PERM_reports.admin");
        });
    }

    @Test
    void aCallRulesCheckIsAtTheCallWithItsArgumentFilledIn() {
        assertThat(checks("ingress:GET /orders/export")).singleElement().satisfies(check -> {
            assertThat(check.mechanism()).isEqualTo("Rule Guard#require (LOCAL)");
            assertThat(check.requirement().authorities()).containsExactly("PERM_orders.export");
        });
    }

    /**
     * The guard's one-permission overload calls its varargs one: the call's rule stands for both, so there is one
     * check, not a second, opaque one inside the guard.
     */
    @Test
    void aVarargsCallAsksForAnyOfItsArgumentsAndTheGuardsOwnCallsAddNothing() {
        assertThat(checks("ingress:GET /orders/audit")).singleElement().satisfies(check ->
                assertThat(check.requirement().operands()).flatExtracting(Requirement::authorities)
                        .containsExactlyInAnyOrder("PERM_audit.read", "PERM_audit.admin"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).noneMatch(message -> message.startsWith("fixtures.customlibrary.Guard"));
    }

    @Test
    void anArgumentThatIsntAConstantLeavesTheCheckOpaqueAndSaysSo() {
        assertThat(checks("ingress:POST /orders/{action}")).singleElement().satisfies(check ->
                assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.EXPRESSION));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("is checked by the rule for call fixtures.customlibrary.Guard#require")
                        .contains("{arg0}"));
    }

    @Test
    void theRulesAreRecordedWithTheGraphsProvidedFacts() {
        assertThat(graph.provided()).filteredOn(fact -> fact.kind() == ProvidedFact.Kind.RULE)
                .extracting(ProvidedFact::subject).containsExactlyInAnyOrder(
                        "annotation fixtures.customlibrary.RequiresPermission",
                        "call fixtures.customlibrary.Guard#require");
        assertThat(graph.findings()).extracting(Finding::message)
                .noneMatch(message -> message.contains("matches nothing in the graph"));
        // The guard is the library's check, which its rule stands for: no hand-rolled one.
        assertThat(graph.findings()).extracting(Finding::kind).doesNotContain(Finding.Kind.UNRECOGNIZED_CHECK);
    }

    /**
     * A mistyped rule would leave the library's checks out of the graph with nothing said.
     */
    @Test
    void aRuleThatMatchesNothingIsReported(@TempDir Path dir) throws IOException {
        Path file = Files.writeString(dir.resolve("authtracer.yaml"), """
                version: 1
                rules:
                  - annotation: fixtures.customlibrary.RequiresPermision
                    requires: "hasAuthority('PERM_{value}')"
                  - call: "fixtures.customlibrary.Guard#requires"
                    requires: "hasAuthority('PERM_{arg0}')"
                """);
        ApplicationGraph mistyped = FixtureScans.scan("customlibrary", ProvidedFacts.load(Optional.of(file),
                Optional.empty(), "customlibrary"));

        assertThat(mistyped.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("LOCAL rule fact on annotation"
                        + " fixtures.customlibrary.RequiresPermision matches nothing in the graph"))
                .anySatisfy(message -> assertThat(message).startsWith("LOCAL rule fact on call"
                        + " fixtures.customlibrary.Guard#requires matches nothing in the graph"));
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().startsWith("Rule ")).toList();
    }
}
