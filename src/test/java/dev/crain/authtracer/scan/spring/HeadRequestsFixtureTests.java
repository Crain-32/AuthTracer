package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0110: Spring MVC runs a GET mapping's handler for HEAD (7.0.9 RequestMethodsRequestCondition), while a rule
 * for GET doesn't match HEAD (7.1.1 PathPatternRequestMatcher): where HEAD gets another rule, and GET doesn't let
 * everyone in, it is a way in of its own.
 */
class HeadRequestsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("headrequests");

    @Test
    void headRunsTheGetHandlerUnderTheRuleForItsOwnMethod() {
        assertThat(rule(graph, "GET /admin/users").requirement().authorities()).containsExactly("ROLE_ADMIN");
        Ingress head = (Ingress) graph.node("ingress:HEAD /admin/users").orElseThrow();
        assertThat(head.handler().key()).isEqualTo(((Ingress) graph.node("ingress:GET /admin/users").orElseThrow())
                .handler().key());
        assertThat(rule(graph, "HEAD /admin/users").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        // No body goes back.
        assertThat(head.response()).isNull();
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("HEAD /admin/users runs the handler of GET /admin/users")
                        .contains("ask it for authenticated where GET needs hasRole(ADMIN)"));
    }

    @Test
    void aHeadThatNeedsSomethingElseIsAWayInToo() {
        assertThat(rule(graph, "HEAD /reports/daily").requirement().authorities()).containsExactly("ROLE_READER");
        assertThat(rule(graph, "GET /reports/daily").requirement().authorities()).containsExactly("ROLE_AUDITOR");
    }

    @Test
    void aGetOpenToEveryoneHasNoHeadOfItsOwn() {
        assertThat(graph.node("ingress:GET /open/info")).isPresent();
        assertThat(graph.node("ingress:HEAD /open/info")).isEmpty();
        assertThat(graph.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("/open/info"));
    }

    @Test
    void aServletsDoGetAnswersHeadUnlessItOverridesDoHead() {
        ApplicationGraph servlets = FixtureScans.scan("headservlets");
        Ingress files = (Ingress) servlets.node("ingress:HEAD /files/**").orElseThrow();
        assertThat(files.handler().key()).isEqualTo("fixtures.headservlets.FilesServlet#doGet(jakarta.servlet.http"
                + ".HttpServletRequest,jakarta.servlet.http.HttpServletResponse)");
        assertThat(rule(servlets, "HEAD /files/**").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        Ingress status = (Ingress) servlets.node("ingress:HEAD /files/status").orElseThrow();
        assertThat(status.handler().key()).startsWith("fixtures.headservlets.StatusServlet#doHead(");
        assertThat(servlets.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("/files/status"));
    }

    @Test
    void aMappingForHeadTakesHeadFromTheGetHandler() {
        Ingress head = (Ingress) graph.node("ingress:HEAD /admin/stats").orElseThrow();
        assertThat(head.handler().key()).endsWith("statsHead()");
        assertThat(graph.findings()).extracting(Finding::message)
                .noneSatisfy(message -> assertThat(message).contains("/admin/stats"));
    }
}
