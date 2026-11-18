package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Checks on Spring Data repository methods, whose implementation Spring Data generates.
 */
class RepositoryFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("repositories");

    @Test
    void methodSecurityOnARepositoryMethod() {
        assertThat(path(graph, "ingress:DELETE /messages/{id}")).contains(
                "location:METHOD:fixtures.repositories.MessageRepository#deleteById(java.lang.Long):@PreAuthorize");
    }

    @Test
    void aQueryThatReadsThePrincipalFiltersTheRows() {
        String id = "location:METHOD:fixtures.repositories.MessageRepository#findInbox():@Query";
        assertThat(path(graph, "ingress:GET /inbox")).contains(id);
        AuthorizationLocation query = (AuthorizationLocation) graph.node(id).orElseThrow();
        assertThat(query.denial().kind()).isEqualTo(AuthorizationLocation.Denial.Kind.FILTER);
        assertThat(query.requirement().expression()).isEqualTo("query rows filtered by principal?.id");
        // The SecurityEvaluationContextExtension bean is there, so the query can evaluate it.
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
    }

    @Test
    void springBootDefinesTheEvaluationContextExtension() {
        assertThat(FixtureScans.scan("bootrepositories").findings())
                .noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
        assertThat(FixtureScans.scan("plainrepositories").findings())
                .anyMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
    }
}
