package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0027: a check counts for an endpoint only on every way it returns.
 */
class BranchesFixtureTests {

    private static final String FIND = "location:METHOD:fixtures.branches.DocService#find(long):@PreAuthorize";
    private static final String FULL = "location:METHOD:fixtures.branches.DocService#full(long):@PreAuthorize";

    private final ApplicationGraph graph = FixtureScans.scan("branches");
    private final List<Exposure> exposures = Exposures.of(graph);

    @Test
    void aReturnWithoutTheCheckLeavesItToTheOtherBranch() {
        assertThat(edge("GET /cached/{id}", FIND).conditional()).isTrue();
        assertThat(requirement("GET /cached/{id}")).isEqualTo("authenticated");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /cached/{id}:")
                        .contains("DocService#find(long)", "runs on some of", "BranchController#cached(long)"));
    }

    @Test
    void branchesWithTheirOwnChecksAskForTheWeakerOne() {
        for (String endpoint : List.of("GET /either/{id}", "GET /split/{id}")) {
            assertThat(edge(endpoint, FIND).conditional()).isTrue();
            assertThat(edge(endpoint, FULL).conditional()).isTrue();
            // ROLE_ADMIN or ROLE_READER: a reader gets in through find.
            assertThat(requirement(endpoint)).as(endpoint).contains("ROLE_ADMIN", "ROLE_READER")
                    .doesNotContain(" and ");
            assertThat(graph.findings()).extracting(Finding::message)
                    .noneMatch(message -> message.startsWith("On " + endpoint + ":"));
        }
    }

    @Test
    void guardClausesAndCatchBlocksDontMakeTheCheckConditional() {
        for (String endpoint : List.of("GET /guarded/{id}", "GET /fallback/{id}")) {
            assertThat(edge(endpoint, FIND).conditional()).as(endpoint).isFalse();
            assertThat(requirement(endpoint)).as(endpoint).contains("ROLE_READER");
            assertThat(graph.findings()).extracting(Finding::message)
                    .noneMatch(message -> message.startsWith("On " + endpoint + ":"));
        }
    }

    @Test
    void aDenialThatIsCaughtAndIgnoredLetsTheRequestThrough() {
        assertThat(requirement("GET /swallowed/{id}")).isEqualTo("authenticated");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /swallowed/{id}:")
                        .contains("Access#requireManager(long)"));
    }

    @Test
    void branchesInsideABranchAreAlternativesToo() {
        // ROLE_ARCHIVIST or ROLE_READER or ROLE_ADMIN, not READER and ADMIN together.
        assertThat(requirement("GET /archived/{id}")).contains("ROLE_ARCHIVIST", "ROLE_READER")
                .doesNotContain(" and ");
        assertThat(graph.findings()).extracting(Finding::message)
                .noneMatch(message -> message.startsWith("On GET /archived/{id}:"));

        assertThat(requirement("GET /peeked/{id}")).isEqualTo("authenticated");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /peeked/{id}:"));
    }

    private Edge edge(String endpoint, String to) {
        return graph.path("ingress:" + endpoint).stream().filter(edge -> edge.to().equals(to)).findFirst()
                .orElseThrow(() -> new AssertionError(to + " not on " + endpoint));
    }

    private String requirement(String endpoint) {
        return exposures.stream().filter(exposure -> exposure.endpoint().equals(endpoint) && exposure.field().isEmpty())
                .findFirst().orElseThrow().requirement();
    }
}
