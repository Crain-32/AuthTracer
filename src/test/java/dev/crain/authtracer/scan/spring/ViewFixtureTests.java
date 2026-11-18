package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.DiffReport;
import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.GraphDiff;
import dev.crain.authtracer.diff.SarifReport;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.FieldSource;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Decision 0035: server-side views expose what their templates read.
 */
class ViewFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("views");

    @Test
    void aViewIsTheResponse() {
        Ingress show = (Ingress) graph.node("ingress:GET /owners/{id}").orElseThrow();
        assertThat(show.response().type()).isEqualTo("view:owners/details");
        // A redirect renders nothing.
        Ingress create = (Ingress) graph.node("ingress:POST /owners/new").orElseThrow();
        assertThat(create.response().type()).doesNotStartWith("view:");
    }

    @Test
    void theFieldsTheTemplateReads() {
        Map<String, String> details = exposures("ingress:GET /owners/{id}");
        assertThat(details).containsOnlyKeys("", "owner.firstName", "owner.lastName", "owner.ssn", "owner.pets",
                "owner.pets[].name");
        assertThat(details.get("owner.firstName")).isEqualTo("ROLE_STAFF");
        // sec:authorize guards what it wraps.
        assertThat(details.get("owner.ssn")).isEqualTo("ROLE_STAFF and ROLE_ADMIN");
        // th:each reads the collection it iterates.
        assertThat(exposures("ingress:GET /owners")).containsOnlyKeys("", "listOwners", "listOwners[].id",
                "listOwners[].lastName");
    }

    @Test
    void aSharedFragmentsGuardIsEachViewsOwn() {
        assertThat(exposures("ingress:GET /owners/{id}/badge").get("owner.ssn")).contains("ROLE_ADMIN")
                .doesNotContain("ROLE_AUDITOR");
        assertThat(exposures("ingress:GET /owners/{id}/audit").get("owner.ssn")).contains("ROLE_ADMIN",
                "ROLE_AUDITOR");
    }

    @Test
    void aFragmentNamedWithoutItsBracesAndAnAuthorizationExpressionInThIf() {
        Map<String, String> card = exposures("ingress:GET /owners/{id}/card");
        // The badge view shows the same fragment under the same guard: each view has its own check.
        assertThat(card.get("owner.ssn")).contains("ROLE_ADMIN");
        assertThat(card.get("owner.lastName")).contains("ROLE_AUDITOR");
    }

    @Test
    void viewsSharingAFragmentKeepTheirOwnChecksAndLines() {
        // A view's templates are read once however many handlers render it: what each view shows of the shared
        // fragment is still its own, and the lines after the fragment are still the view's.
        ApplicationGraph shared = FixtureScans.scan("sharedfragments");
        Map<String, AuthorizationLocation> summary = fieldChecks(shared, "ingress:GET /employees/{id}");
        Map<String, AuthorizationLocation> profile = fieldChecks(shared, "ingress:GET /employees/{id}/profile");
        assertThat(summary).containsOnlyKeys("employee.phone", "employee.salary");
        assertThat(profile).containsOnlyKeys("employee.phone", "employee.salary");
        assertThat(summary.get("employee.phone").id()).contains("view:employees/summary");
        assertThat(profile.get("employee.phone").id()).contains("view:employees/profile");
        assertThat(summary.get("employee.phone").target())
                .isEqualTo(CodeRef.ofClass("templates/fragments/contact.html").atLine(5));
        assertThat(profile.get("employee.phone").target())
                .isEqualTo(CodeRef.ofClass("templates/fragments/contact.html").atLine(5));
        assertThat(summary.get("employee.salary").target())
                .isEqualTo(CodeRef.ofClass("templates/employees/summary.html").atLine(5));
        assertThat(profile.get("employee.salary").target())
                .isEqualTo(CodeRef.ofClass("templates/employees/profile.html").atLine(10));
        Map<String, String> exposures = Exposures.of(shared).stream()
                .filter(exposure -> exposure.ingress().equals("ingress:GET /employees/{id}/profile"))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
        // The profile shows the fragment inside a guard of its own.
        assertThat(exposures.get("employee.phone")).isEqualTo("ROLE_MANAGER and ROLE_STAFF");
        assertThat(summary.get("employee.phone").requirement().authorities()).containsExactly("ROLE_STAFF");
        // Another handler of the same view gets the same checks.
        assertThat(fieldChecks(shared, "ingress:GET /employees/{id}/print")).isEqualTo(summary);
    }

    private static Map<String, AuthorizationLocation> fieldChecks(ApplicationGraph graph, String ingress) {
        return FixtureScans.path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(check -> check.scope() == AuthorizationLocation.Scope.FIELD)
                .collect(Collectors.toMap(check -> check.field().replace(':', '.'), check -> check));
    }

    @Test
    void aModelHandedOverAsAMapIsReadToo() {
        assertThat(exposures("ingress:GET /owners/search")).containsOnlyKeys("", "listOwners", "listOwners[].id",
                "listOwners[].lastName");
        assertThat(graph.flows("ingress:GET /owners/search")).contains(Flow.local("ingress:GET /owners/search",
                "field:fixtures.views.Owner.lastName", "field:view:owners/list.listOwners[]:lastName",
                FieldSource.DIRECT));
    }

    @Test
    void viewFieldsComeFromTheDomainFields() {
        // Through Optional<Owner>.orElseThrow() and Page<Owner>.getContent().
        assertThat(graph.flows("ingress:GET /owners/{id}")).contains(Flow.local("ingress:GET /owners/{id}",
                "field:fixtures.views.Pet.name", "field:view:owners/details.owner:pets[]:name", FieldSource.DIRECT));
        assertThat(graph.flows("ingress:GET /owners")).contains(Flow.local("ingress:GET /owners",
                "field:fixtures.views.Owner.lastName", "field:view:owners/list.listOwners[]:lastName",
                FieldSource.DIRECT));
    }

    @Test
    void aHandlerRendersEveryViewItReturnsWithAMapModel() {
        ApplicationGraph choices = FixtureScans.scan("viewchoices");
        Ingress show = (Ingress) choices.node("ingress:GET /people/{id}").orElseThrow();
        assertThat(show.response().type()).isEqualTo("view:people/badge,people/card");
        Map<String, String> fields = Exposures.of(choices).stream()
                .filter(exposure -> exposure.ingress().equals(show.id()))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
        assertThat(fields).containsOnlyKeys("", "person.name", "person.ssn");
        // Shown under either guard: either one shows it (data-sec-authorize is sec:authorize too).
        assertThat(fields.get("person.ssn")).isEqualTo("any of [ROLE_ADMIN, ROLE_AUDITOR]");
    }

    private Map<String, String> exposures(String ingress) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.ingress().equals(ingress))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
    }

    @Test
    void droppingSecAuthorizeFromATemplateWeakensTheField(@TempDir Path project) throws Exception {
        // The head is the same view with the template's sec:authorize around owner.ssn removed.
        String guard = graph.nodes(AuthorizationLocation.class).stream()
                .filter(location -> location.mechanism().equals("sec:authorize")
                        && location.target().className().endsWith("owners/details.html"))
                .map(AuthorizationLocation::id).findFirst().orElseThrow();
        ApplicationGraph head = new ApplicationGraph(graph.schemaVersion(), graph.service(), "head", graph.port(),
                graph.authoritySource(), graph.nodes().stream().filter(node -> !node.id().equals(guard)).toList(),
                graph.edges().stream().filter(edge -> !edge.to().equals(guard)).toList(), graph.flows(),
                graph.provided(), graph.findings());
        DiffReport report = GraphDiff.compare(graph, head);
        assertThat(report.changes()).filteredOn(change -> change.kind() == DiffReport.Kind.WEAKENED)
                .singleElement().satisfies(change -> assertThat(change.field()).isEqualTo("owner.ssn"));
        // SARIF points at the template line the check was on.
        Path template = project.resolve("src/main/resources/templates/owners/details.html");
        Files.createDirectories(template.getParent());
        Files.copy(Path.of("src/fixtures/resources/views/templates/owners/details.html"), template);
        String sarif = SarifReport.write(report, Map.of(graph.service(), project));
        assertThat(sarif).contains("src/main/resources/templates/owners/details.html").contains("\"startLine\" : 6");
    }
}
