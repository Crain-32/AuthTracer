package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class AdvisorsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("advisors");

    @Test
    void anAdvisorBeanTurnsAnAnnotationBackOn() {
        assertThat(checks(graph, "GET /reports")).extracting(AuthorizationLocation::mechanism)
                .containsExactly("Advisor protectServices()", "@PreAuthorize");
        assertThat(check(graph, "GET /reports", "@PreAuthorize").requirement().authorities())
                .containsExactly("ROLE_ANALYST");
        assertThat(graph.findings()).extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("@PostAuthorize", "prePostEnabled = false"));
    }

    @Test
    void aCustomManagerDecidesInsteadOfTheAnnotation() {
        assertThat(check(graph, "GET /reports/secret", "@Secured").requirement().authorities())
                .containsExactly("ROLE_CUSTOM");
    }

    @Test
    void aPointcutAdvisorGuardsEveryMatchedMethodFirst() {
        AuthorizationLocation advisor = check(graph, "GET /reports/latest", "Advisor protectServices()");
        assertThat(advisor.requirement().authorities()).containsExactly("ROLE_USER");
        assertThat(advisor.routePattern()).isEqualTo("execution(* fixtures.advisors.*Service.*(..))");
        assertThat(checks(graph, "GET /audit")).extracting(AuthorizationLocation::mechanism)
                .doesNotContain("Advisor protectServices()");
    }

    @Test
    void aTrailingEllipsisMatchesEveryTypeBelowThePackage() {
        AuthorizationLocation advisor = check(graph, "GET /admin/ledger", "Advisor protectAdmin()");
        assertThat(advisor.requirement().authorities()).containsExactly("ROLE_STAFF");
        assertThat(checks(graph, "GET /reports")).extracting(AuthorizationLocation::mechanism)
                .doesNotContain("Advisor protectAdmin()");
    }

    @Test
    void aPointcutAuthTracerCantReadIsReportedNotDropped() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("protectTrails()"));
    }

    @Test
    void anAdvisorWithoutTheInfrastructureRoleNeverRuns() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("jsr250()", "ROLE_INFRASTRUCTURE"))
                .anySatisfy(message -> assertThat(message).contains("@RolesAllowed", "jsr250Enabled"));
    }

    @Test
    void aPostCheckOutsideTheTransactionDecidesAfterTheCommit() {
        ApplicationGraph transactions = FixtureScans.scan("transactions");
        assertThat(transactions.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.CHECK_AFTER_COMMIT)
                .extracting(Finding::message).singleElement().asString()
                .contains("@PostAuthorize", "OrderService#approve", "LOWEST_PRECEDENCE");
        assertThat(FixtureScans.scan("transactionsinside").findings())
                .noneMatch(finding -> finding.kind() == Finding.Kind.CHECK_AFTER_COMMIT);
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST).toList();
    }

    private static AuthorizationLocation check(ApplicationGraph graph, String ingress, String mechanism) {
        return checks(graph, ingress).stream().filter(location -> location.mechanism().equals(mechanism))
                .findFirst().orElseThrow();
    }
}
