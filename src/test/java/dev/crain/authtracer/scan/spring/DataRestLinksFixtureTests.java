package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0114: Spring Data REST's association resources, read through the owner's repository, and a
 * RepositoryRestConfigurer's base path and exposure.
 */
class DataRestLinksFixtureTests {

    private static final String TELLER = "location:METHOD:fixtures.datarestlinks.AccountRepository#findById(java.lang"
            + ".Long):@PreAuthorize";
    private static final String AUDITOR = "location:METHOD:fixtures.datarestlinks.TransactionRepository#findById(java"
            + ".lang.Long):@PreAuthorize";

    private static final String MANAGER = "location:METHOD:fixtures.datarestlinks.BranchRepository#findById(java"
            + ".lang.Long):@PreAuthorize";

    private final ApplicationGraph graph = FixtureScans.scan("datarestlinks");

    @Test
    void anAssociationIsReadThroughItsOwnersRepository() {
        Ingress transactions = (Ingress) graph.node("ingress:GET /api/accounts/{id}/transactions").orElseThrow();
        assertThat(transactions.response().type()).isEqualTo("fixtures.datarestlinks.Transaction");
        assertThat(transactions.response().many()).isTrue();
        // The account's check runs, the transaction repository's doesn't.
        List<String> steps = path(graph, transactions.id());
        assertThat(steps).anySatisfy(step -> assertThat(step).startsWith(TELLER))
                .noneSatisfy(step -> assertThat(step).startsWith(AUDITOR));
        assertThat(graph.node("ingress:GET /api/accounts/{id}/transactions/{propertyId}")).isPresent();
    }

    @Test
    void linkingACollectionMayLookNothingUpInTheLinkedRepository() {
        // Found by conformanceTest: a teller PUTs no URIs, so no transaction is looked up, and unlinks them all.
        assertThat(path(graph, "ingress:PUT /api/accounts/{id}/transactions"))
                .anySatisfy(step -> assertThat(step).startsWith(TELLER))
                .noneSatisfy(step -> assertThat(step).startsWith(AUDITOR));
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains(
                "ingress:POST /api/accounts/{id}/transactions", "ingress:PATCH /api/accounts/{id}/transactions",
                "ingress:DELETE /api/accounts/{id}/transactions/{propertyId}",
                "ingress:PUT /api/accounts/{id}/branch", "ingress:DELETE /api/accounts/{id}/branch")
                // One branch: no POST, no PATCH, no item of its own; the collection is unlinked an item at a time.
                .doesNotContain("ingress:POST /api/accounts/{id}/branch", "ingress:PATCH /api/accounts/{id}/branch",
                        "ingress:GET /api/accounts/{id}/branch/{propertyId}",
                        "ingress:DELETE /api/accounts/{id}/transactions");
    }

    @Test
    void linkingOneEntityLooksItUpInItsRepository() {
        assertThat(path(graph, "ingress:PUT /api/accounts/{id}/branch"))
                .anySatisfy(step -> assertThat(step).startsWith(TELLER))
                .anySatisfy(step -> assertThat(step).startsWith(MANAGER));
        assertThat(path(graph, "ingress:GET /api/accounts/{id}/branch"))
                .noneSatisfy(step -> assertThat(step).startsWith(MANAGER));
    }

    @Test
    void anAssociationsPathAndExposureAreItsRestResources() {
        assertThat(graph.node("ingress:GET /api/accounts/{id}/home")).isPresent();
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .noneSatisfy(id -> assertThat(id).contains("homeBranch", "formerBranch"));
    }

    @Test
    void aQueryMethodOfAnApplicationSuperInterfaceIsASearch() {
        assertThat(graph.node("ingress:GET /api/accounts/search/findByOwner")).isPresent();
    }

    @Test
    void aConfigurersBasePathIsReadAndItsExposureReported() {
        assertThat(graph.node("ingress:GET /api/transactions")).isPresent();
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("The RepositoryRestConfigurer fixtures.datarestlinks.RestConfig sets what"
                                + " AuthTracer doesn't read (setRepositoryDetectionStrategy)"));
    }
}
