package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0027: a call more than one bean answers runs one of them, so it asks for the weakest one's checks.
 */
class DispatchFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("dispatch");

    @Test
    void aBeanWithoutTheCheckLeavesTheCallOpen() {
        assertThat(endpoint("ingress:GET /accounts/{id}")).isEqualTo("none");
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("@PreAuthorize on fixtures.dispatch.CheckedAccounts#find(long)")
                        .contains("fixtures.dispatch.OpenAccounts#find(long) runs without it"));
    }

    @Test
    void beansWithDifferentChecksAskForEitherOne() {
        String split = "location:SPLIT:fixtures.dispatch.DispatchController#report():calls:"
                + "fixtures.dispatch.Reports#report()";
        assertThat(path(graph, "ingress:GET /reports")).contains(split);
        Requirement either = ((AuthorizationLocation) graph.node(split).orElseThrow()).requirement();
        assertThat(either.kind()).isEqualTo(Requirement.Kind.OR);
        assertThat(either.operands()).extracting(Requirement::authorities).map(Set::copyOf)
                .containsExactlyInAnyOrder(Set.of("ROLE_MANAGER"), Set.of("ROLE_AUDITOR"));
    }

    @Test
    void aBaseMethodEveryBeanOverridesIsNotAnAlternative() {
        assertThat(endpoint("ingress:GET /exports/{id}")).contains("ROLE_FINANCE");
        // The OpenAPI delegate's default answers for no bean.
        assertThat(endpoint("ingress:GET /users/{id}")).isEqualTo("ROLE_USERS");
        assertThat(bypassed("GET /exports/{id}")).isEmpty();
        assertThat(bypassed("GET /users/{id}")).isEmpty();
    }

    @Test
    void aBeanMethodRegistersTheClassItCreates() {
        assertThat(endpoint("ingress:GET /notifications/{id}")).isEqualTo("ROLE_MAILER");
        assertThat(bypassed("GET /notifications/{id}")).isEmpty();
    }

    @Test
    void aDecoratorThatRecursesIntoItselfIsNotAWayWithoutTheCheck() {
        assertThat(endpoint("ingress:GET /ledger/{id}")).contains("ROLE_LEDGER");
        assertThat(bypassed("GET /ledger/{id}")).isEmpty();
    }

    @Test
    void aBridgeIsWalkedThroughToTheMethodItCalls() {
        assertThat(path(graph, "ingress:GET /query"))
                .contains("location:METHOD:fixtures.dispatch.Checks#query():@PreAuthorize");
        assertThat(endpoint("ingress:GET /query")).isEqualTo("ROLE_QUERY");
    }

    @Test
    void aClassCallReachesTheInterfaceDefaultItInherits() {
        assertThat(path(graph, "ingress:GET /audits/{id}"))
                .contains("location:METHOD:fixtures.dispatch.Checks#audit(long):@PreAuthorize");
        assertThat(endpoint("ingress:GET /audits/{id}")).isEqualTo("ROLE_AUDIT");
    }

    private List<String> bypassed(String endpoint) {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .map(Finding::message).filter(message -> message.startsWith("On " + endpoint + ":")).toList();
    }

    private String endpoint(String ingress) {
        return Exposures.of(graph).stream()
                .filter(exposure -> exposure.ingress().equals(ingress) && exposure.field().isEmpty())
                .map(Exposures.Exposure::requirement).findFirst().orElseThrow();
    }
}
