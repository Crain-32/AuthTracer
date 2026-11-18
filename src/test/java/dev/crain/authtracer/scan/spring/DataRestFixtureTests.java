package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0040: repositories Spring Data REST exports.
 */
class DataRestFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("datarest");

    @Test
    void anExportedRepositoryIsACollectionResource() {
        assertThat(graph.nodes()).filteredOn(Ingress.class::isInstance).map(node -> ((Ingress) node).id())
                .contains("ingress:GET /persons", "ingress:POST /persons", "ingress:GET /persons/{id}",
                        "ingress:PUT /persons/{id}", "ingress:PATCH /persons/{id}",
                        "ingress:GET /persons/search/findByName", "ingress:GET /audit")
                // deleteById isn't exported; neither are the hidden and package-private repositories.
                .doesNotContain("ingress:DELETE /persons/{id}", "ingress:POST /audit")
                .noneMatch(id -> id.contains("secret") || id.contains("hidden") || id.contains("internal"));
        assertThat(((Ingress) graph.node("ingress:GET /persons").orElseThrow()).response().many()).isTrue();
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals("ingress:GET /persons/{id}"))
                .extracting(Exposures.Exposure::field).contains("name", "ssn");
    }

    @Test
    void theRepositoryMethodsChecksApply() {
        assertThat(path(graph, "ingress:POST /persons")).contains("location:METHOD:"
                + "fixtures.datarest.PersonRepository#save(fixtures.datarest.Person):@PreAuthorize");
        assertThat(((Ingress) graph.node("ingress:POST /persons").orElseThrow()).handler().method())
                .isEqualTo("save(fixtures.datarest.Person)");
        assertThat(path(graph, "ingress:GET /persons").stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast))
                .extracting(AuthorizationLocation::mechanism).containsExactly("authorizeHttpRequests");
    }

    @Test
    void theCrudMethodsAreTheOnesSpringDataPicks() {
        String delete = "location:METHOD:fixtures.datarest.PurchaseRepository#delete(fixtures.datarest.Purchase)"
                + ":@PreAuthorize";
        String findById = "location:METHOD:fixtures.datarest.PurchaseRepository#findById(java.lang.Long)"
                + ":@PreAuthorize";
        assertThat(((Ingress) graph.node("ingress:DELETE /purchases/{id}").orElseThrow()).handler().method())
                .isEqualTo("delete(fixtures.datarest.Purchase)");
        // The item is looked up before it is deleted or replaced.
        assertThat(path(graph, "ingress:DELETE /purchases/{id}")).containsSubsequence(findById, delete);
        assertThat(path(graph, "ingress:PUT /purchases/{id}")).contains(findById);
        assertThat(path(graph, "ingress:GET /purchases")).contains("location:METHOD:"
                + "fixtures.datarest.PurchaseRepository#findAll(org.springframework.data.domain.Pageable)"
                + ":@PreAuthorize");
    }

    @Test
    void eventHandlersRunInsideTheirRequests() {
        // Before the save's own check, the create handler's; a delete runs the after-delete handler, which takes
        // any entity; the Secret handler isn't for persons.
        assertThat(path(graph, "ingress:POST /persons")).containsSubsequence(
                "location:METHOD:fixtures.datarest.PersonEvents#beforeCreate(fixtures.datarest.Person):@PreAuthorize",
                "location:METHOD:fixtures.datarest.PersonRepository#save(fixtures.datarest.Person):@PreAuthorize");
        assertThat(path(graph, "ingress:PUT /persons/{id}")).noneMatch(id -> id.contains("PersonEvents"));
        assertThat(path(graph, "ingress:DELETE /notes/{id}")).last().isEqualTo(
                "location:METHOD:fixtures.datarest.PersonEvents#afterDelete(java.lang.Object):@PreAuthorize");
    }

    @Test
    void importedWithoutBootOnAGenericBaseRepository() {
        ApplicationGraph imported = FixtureScans.scan("datarestimport");
        // The @NoRepositoryBean base isn't exported; Ledger's own @RestResource(exported = false) hides its public
        // repository; a search method at its own path, not the default method; invoices aren't read one by one.
        assertThat(imported.nodes(Ingress.class)).extracting(Ingress::id).containsExactlyInAnyOrder(
                "ingress:GET /customers", "ingress:POST /customers", "ingress:GET /customers/{id}",
                "ingress:PUT /customers/{id}", "ingress:PATCH /customers/{id}", "ingress:DELETE /customers/{id}",
                "ingress:GET /customers/search/by-name", "ingress:GET /invoices", "ingress:POST /invoices",
                "ingress:PUT /invoices/{id}", "ingress:PATCH /invoices/{id}", "ingress:DELETE /invoices/{id}");
        assertThat(((Ingress) imported.node("ingress:GET /customers/{id}").orElseThrow()).response().type())
                .isEqualTo("fixtures.datarestimport.Customer");
        // A handler for the entities' base class, or an interface they implement, runs for each of them.
        assertThat(path(imported, "ingress:PUT /invoices/{id}")).contains(
                "location:METHOD:fixtures.datarestimport.AuditHandler#beforeSave(fixtures.datarestimport"
                        + ".AuditedEntity):@PreAuthorize",
                "location:METHOD:fixtures.datarestimport.AuditHandler#beforeSaveOwned(fixtures.datarestimport"
                        + ".Owned):@PreAuthorize");
    }

    @Test
    void theDetectionStrategies() {
        // annotated: only what is annotated as exported, under the base path.
        assertThat(dataRestIngress("datarestannotated")).containsExactlyInAnyOrder("ingress:GET /api/catalog",
                "ingress:POST /api/catalog", "ingress:GET /api/catalog/{id}", "ingress:PUT /api/catalog/{id}",
                "ingress:PATCH /api/catalog/{id}", "ingress:DELETE /api/catalog/{id}");
        // visibility: the public repository, though annotated not to be; not the annotated package-private one.
        assertThat(dataRestIngress("datarestvisibility")).allMatch(id -> id.contains("/devices"))
                .contains("ingress:GET /devices");
        // all: every repository.
        assertThat(dataRestIngress("datarestall")).contains("ingress:GET /tenants", "ingress:GET /plans");
    }

    private static List<String> dataRestIngress(String fixture) {
        return FixtureScans.scan(fixture).nodes(Ingress.class).stream().map(Ingress::id)
                .filter(id -> !id.contains("/actuator/") && !id.contains("api-docs") && !id.contains("swagger-ui"))
                .toList();
    }
}
