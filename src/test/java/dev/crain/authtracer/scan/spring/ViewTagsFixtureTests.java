package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Collectors;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0081 (AUTHZ-14): view guards by URL ask what the request rules ask; ACL guards ask hasPermission; each
 * handler's view shows its own model.
 */
class ViewTagsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("viewtags");

    @Test
    void thymeleafUrlGuardsAskWhatTheRequestRulesAskOfThatRequest() {
        Map<String, String> dashboard = exposures("ingress:GET /dashboard");
        assertThat(dashboard.get("report.headcount")).isEqualTo("ROLE_USER_ADMIN");
        // "POST /admin/purge": the method given first.
        assertThat(dashboard.get("report.purged")).isEqualTo("ROLE_OPS");
        // A URL the rules permit shows to whoever sees the page.
        assertThat(dashboard.get("report.news")).isEqualTo(dashboard.get("report.title"));
    }

    @Test
    void aclGuardsAskForEveryPermission() {
        assertThat(exposures("ingress:GET /dashboard").get("report.notes"))
                .contains("hasPermission(report,'READ')", "hasPermission(report,'WRITE')");
        assertThat(exposures("ingress:GET /contacts/{id}").get("contact.phone"))
                .contains("hasPermission(contact,'ADMINISTRATION')");
        assertThat(exposures("ingress:GET /reports").get("report.notes")).contains("hasPermission(report,'READ')");
    }

    @Test
    void jspAndFreeMarkerUrlGuardsWithAMethodAndAPathVariable() {
        Map<String, String> contact = exposures("ingress:GET /contacts/{id}");
        assertThat(contact.get("contact.email")).isEqualTo("ROLE_ADMIN");
        assertThat(contact.get("contact.notes")).isEqualTo("ROLE_USER_ADMIN");
        assertThat(exposures("ingress:GET /reports").get("report.headcount")).isEqualTo("ROLE_ADMIN");
    }

    @Test
    void handlersRenderingOneViewWithDifferentModelsEachShowTheirOwn() {
        assertThat(exposures("ingress:GET /dashboard")).containsKey("band.top");
        assertThat(exposures("ingress:GET /dashboard/lite")).doesNotContainKey("band.top")
                .containsKey("report.headcount");
        assertThat(response("ingress:GET /dashboard")).isEqualTo("view:admin/dashboard (DashboardController#dashboard)");
        // The same model as another handler's: the same view.
        assertThat(response("ingress:GET /dashboard/print")).isEqualTo(response("ingress:GET /dashboard/lite"))
                .isEqualTo("view:admin/dashboard (DashboardController#lite)");
        // A view no other handler renders differently keeps its name.
        assertThat(response("ingress:GET /reports")).isEqualTo("view:reports/summary");
    }

    @Test
    void aStringAnInheritedHandlerReturnsUnderARestControllerIsItsBody() {
        assertThat(response("ingress:GET /status")).isEqualTo("java.lang.String");
    }

    private String response(String ingress) {
        return ((Ingress) graph.node(ingress).orElseThrow()).response().type();
    }

    private Map<String, String> exposures(String ingress) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.ingress().equals(ingress))
                .collect(Collectors.toMap(Exposures.Exposure::field, Exposures.Exposure::requirement));
    }
}
