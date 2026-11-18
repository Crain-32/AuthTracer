package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * ROLE-04 and decision 0037 with a DefaultAuthorizationManagerFactory set up by hand: its RoleHierarchy, a role
 * prefix it can't read, and a factors manager as its additional authorization.
 */
class MfaAdditionalFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("mfaadditional");

    @Test
    void theFactoryWidensRolesByTheHierarchyItIsGivenAndAddsTheFactors() {
        Requirement reports = rule(graph, "GET /reports/daily").requirement();
        assertThat(reports.kind()).isEqualTo(Kind.AND);
        assertThat(reports.operands().getFirst().authorities()).containsExactly("ROLE_ADMIN", "ROLE_USER");
        assertThat(reports.operands().getLast().authorities()).containsExactly("FACTOR_OTT");
        // Neither role is implied by another: hasAllRoles is as written.
        Requirement approvals = rule(graph, "GET /approvals/pending").requirement();
        assertThat(approvals.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ALL_AUTHORITIES, Kind.ALL_AUTHORITIES);
        assertThat(approvals.operands().getFirst().authorities()).containsExactly("ROLE_AUDITOR", "ROLE_SIGNER");
    }

    @Test
    void aNegatedRuleNegatesTheFactorsWithIt() {
        // 7.1.1: not() negates the factory's hasRole manager, which already requires the factors.
        Requirement transfers = rule(graph, "GET /transfers/new").requirement();
        assertThat(transfers.kind()).isEqualTo(Kind.NOT);
        Requirement negated = transfers.operands().getFirst();
        assertThat(negated.kind()).isEqualTo(Kind.AND);
        assertThat(negated.operands()).flatExtracting(Requirement::authorities)
                .containsExactly("ROLE_FROZEN", "FACTOR_OTT");
    }

    @Test
    void anExpressionTheFactoryDoesntBuildKeepsNoFactors() {
        Requirement profile = rule(graph, "GET /users/{id}/profile").requirement();
        assertThat(profile.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(profile.expression()).startsWith("hasVariable(id).equalTo(");
    }

    @Test
    void factorsListedByArraysAsListAreReadForTheUsersNamed() {
        Requirement home = rule(FixtureScans.scan("mfausers"), "GET /home").requirement();
        assertThat(home.operands().getLast().expression())
                .isEqualTo("factors FACTOR_OTT, FACTOR_WEBAUTHN when the user is admin");
    }

    @Test
    void aRolePrefixThatIsntAConstantIsReported() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .startsWith("The AuthorizationManagerFactory bean fixtures.mfaadditional.MfaAdditionalConfig"
                                + "#authorizationManagerFactory(java.lang.String) does not set its role prefix from a"
                                + " constant"));
    }
}
