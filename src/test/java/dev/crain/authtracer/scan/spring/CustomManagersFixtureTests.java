package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Denial;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0064 (AUTHZ-01, AUTHZ-02, DENY-04): custom AuthorizationManagers, as the code that decides their checks.
 */
class CustomManagersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("custommanagers");

    @Test
    void aManagerCreatedInTheChainIsDecidedByItsAuthorizeMethod() {
        Requirement opa = rule(graph, "GET /opa/check").requirement();
        assertThat(opa.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(opa.expression()).isEqualTo("access(OpaAuthorizationManager)");
        assertThat(opa.decidedBy().key()).isEqualTo("fixtures.custommanagers.OpaAuthorizationManager#authorize("
                + "java.util.function.Supplier,org.springframework.security.web.access.intercept"
                + ".RequestAuthorizationContext)");
    }

    @Test
    void aLambdaIsDecidedByItsBody() {
        Requirement weekdays = rule(graph, "GET /weekdays/plan").requirement();
        assertThat(weekdays.decidedBy().className()).isEqualTo("fixtures.custommanagers.CustomManagersConfig");
        assertThat(weekdays.decidedBy().method()).startsWith("lambda$");
    }

    @Test
    void aManagerHandedInIsFoundByItsTypeOrItsName() {
        assertThat(rule(graph, "GET /office/printers").requirement().decidedBy().className())
                .isEqualTo("fixtures.custommanagers.OfficeHours");
        // The field is typed as the interface: of the manager beans, the one named partners.
        assertThat(rule(graph, "GET /partners/catalog").requirement().decidedBy().className())
                .isEqualTo("fixtures.custommanagers.Partners");
        Requirement either = rule(graph, "GET /either/report").requirement();
        assertThat(either.kind()).isEqualTo(Kind.OR);
        assertThat(either.operands().get(1).decidedBy().className()).isEqualTo("fixtures.custommanagers.OfficeHours");
    }

    @Test
    void eachManagerAuthTracerCantReduceIsAFinding() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(finding -> finding.location().className())
                .contains("fixtures.custommanagers.OpaAuthorizationManager", "fixtures.custommanagers.OfficeHours",
                        "fixtures.custommanagers.Partners", "fixtures.custommanagers.AuditManager");
    }

    @Test
    void anAdvisorsManagerThatHandlesDenialsHandlesThem() {
        AuthorizationLocation entries = path(graph, "ingress:GET /ledger").stream()
                .map(id -> graph.node(id).orElseThrow()).filter(AuthorizationLocation.class::isInstance)
                .map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals("@PreAuthorize")).findFirst().orElseThrow();
        assertThat(entries.requirement().kind()).isEqualTo(Kind.AND);
        assertThat(entries.requirement().operands().get(1).decidedBy().className())
                .isEqualTo("fixtures.custommanagers.AuditManager");
        assertThat(entries.denial()).isEqualTo(new Denial(Denial.Kind.HANDLER, "fixtures.custommanagers.AuditManager"));
    }
}
