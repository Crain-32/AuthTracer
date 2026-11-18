package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.TreeSet;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0065: what decision code decides, read from its body.
 */
class DecisionCodeFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("decisioncode");

    @Test
    void aBeanMethodThatAsksTheRootIsThatRootFunction() {
        Requirement admin = preAuthorize("GET /admin").requirement();
        assertThat(admin.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(admin.authorities()).containsExactly("ROLE_ADMIN");
        assertThat(admin.expression()).isEqualTo("@rules.isAdmin(#root)");
        assertThat(admin.decidedBy().className()).isEqualTo("fixtures.decisioncode.AccessRules");
    }

    @Test
    void authorityComparisonsAreTheAuthoritiesTheyCompare() {
        Requirement operations = preAuthorize("GET /operations").requirement();
        assertThat(operations.kind()).isEqualTo(Kind.OR);
        assertThat(operations.operands()).extracting(Requirement::authorities)
                .containsExactly(new TreeSet<>(List.of("ROLE_OPS")), new TreeSet<>(List.of("ROLE_SRE")));
    }

    @Test
    void codeThatAlwaysGrantsIsPermitAllInDisguise() {
        assertThat(preAuthorize("GET /open").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /abstaining/check").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_GRANTED)
                .extracting(finding -> finding.location().className())
                .contains("fixtures.decisioncode.AccessRules", "fixtures.decisioncode.Abstaining",
                        "fixtures.decisioncode.Lenient");
    }

    @Test
    void codeThatAlwaysDeniesIsReported() {
        assertThat(preAuthorize("GET /closed").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("closed()"));
    }

    @Test
    void aThrownDenialIsPartOfTheDecision() {
        assertThat(preAuthorize("GET /audit").requirement().authorities()).containsExactly("ROLE_AUDITOR");
        assertThat(graph.findings()).noneMatch(finding -> finding.message().contains("auditor("));
    }

    @Test
    void aManagerThatDelegatesToABuiltInOneIsThatOne() {
        assertThat(rule(graph, "GET /delegated/check").requirement().authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void anEvaluatorThatGrantsEverythingAdmitsAnyone() {
        Requirement report = preAuthorize("GET /reports/{id}").requirement();
        assertThat(report.kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(report.decidedBy().className()).isEqualTo("fixtures.decisioncode.Lenient");
    }

    @Test
    void codeThatReadsAStoreIsLiveAndStaysCustom() {
        AuthorizationLocation document = preAuthorize("GET /documents/{id}");
        assertThat(document.requirement().kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(document.freshness()).isEqualTo(AuthoritySource.Freshness.LIVE);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("owns(", "DocumentRepository#findById", "Live"));
        assertThat(preAuthorize("GET /admin").freshness()).isNull();
    }

    @Test
    void whatARemoteManagerCallsIsAnEgressRightAfterItsCheck() {
        List<String> policy = path(graph, "ingress:GET /policy/check");
        AuthorizationLocation check = (AuthorizationLocation) graph.node(policy.getFirst()).orElseThrow();
        assertThat(check.freshness()).isEqualTo(AuthoritySource.Freshness.LIVE);
        assertThat(graph.node(policy.get(1)).orElseThrow()).isInstanceOf(Egress.class);
        assertThat(((Egress) graph.node(policy.get(1)).orElseThrow()).uriTemplate()).contains("/v1/data/authz/allow");
    }

    @Test
    void rootFunctionsForHowTheCallerSignedIn() {
        assertThat(preAuthorize("GET /fully").requirement().kind()).isEqualTo(Kind.FULLY_AUTHENTICATED);
        // isRememberMe() || isAuthenticated(): the second way's !isRememberMe() is dropped.
        assertThat(preAuthorize("GET /remembered").requirement().operands()).extracting(Requirement::kind)
                .containsExactlyInAnyOrder(Kind.REMEMBER_ME, Kind.AUTHENTICATED);
        assertThat(preAuthorize("GET /guest").requirement().kind()).isEqualTo(Kind.ANONYMOUS);
    }

    @Test
    void theContextsAuthenticationIsNeverNullAndItsAuthoritySetIsRead() {
        Requirement billing = preAuthorize("GET /billing").requirement();
        assertThat(billing.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(billing.authorities()).containsExactly("ROLE_BILLING");
    }

    @Test
    void aBoxedAnswerAReturnedManagerOrAManagersDecisionIsWhatItHolds() {
        assertThat(preAuthorize("GET /boxed").requirement().authorities()).containsExactly("ROLE_BOXED");
        assertThat(preAuthorize("GET /managed").requirement().authorities()).containsExactly("ROLE_MANAGER");
        Requirement either = rule(graph, "GET /either/check").requirement();
        assertThat(either.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(either.authorities()).containsExactlyInAnyOrder("ROLE_FINANCE", "ROLE_HR");
    }

    @Test
    void aWayThatContradictsItselfNeverGrants() {
        // hasRole('SOLO') && !hasRole('SOLO')
        assertThat(preAuthorize("GET /contradiction").requirement().kind()).isEqualTo(Kind.DENY_ALL);
    }

    @Test
    void unboxingAConstantBranchAnyThrowAndANullCheck() {
        assertThat(preAuthorize("GET /unboxed").requirement().authorities()).containsExactly("ROLE_UNBOXED");
        assertThat(preAuthorize("GET /strict").requirement().authorities()).containsExactly("ROLE_STRICT");
        assertThat(preAuthorize("GET /legal").requirement().authorities()).containsExactly("ROLE_LEGAL");
        assertThat(rule(graph, "GET /guarded/check").requirement().authorities()).containsExactly("ROLE_GUARD");
    }

    @Test
    void aLoopAnotherObjectsAnswerOrANumberLeavesItUndecided() {
        Requirement anyRole = preAuthorize("GET /any-role").requirement();
        assertThat(anyRole.kind()).isEqualTo(Kind.EXPRESSION);
        // Varargs: the one method of the name, though the call passes more arguments than it declares.
        assertThat(anyRole.decidedBy().method()).startsWith("anyRole(");
        assertThat(preAuthorize("GET /member").requirement().kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(preAuthorize("GET /level/{level}").requirement().kind()).isEqualTo(Kind.EXPRESSION);
    }

    @Test
    void aMethodTheBeanDoesNotDeclareIsDecidedByItsClass() {
        Requirement inherited = preAuthorize("GET /inherited").requirement();
        assertThat(inherited.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(inherited.decidedBy().className()).isEqualTo("fixtures.decisioncode.AccessRules");
        assertThat(inherited.decidedBy().method()).isNull();
    }

    @Test
    void booleanTrueAlwaysGrants() {
        assertThat(preAuthorize("GET /always").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void aTryBlockOrASwitchLeavesItUndecided() {
        assertThat(preAuthorize("GET /careful").requirement().kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(preAuthorize("GET /named").requirement().kind()).isEqualTo(Kind.EXPRESSION);
    }

    private AuthorizationLocation preAuthorize(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals("@PreAuthorize")).findFirst().orElseThrow();
    }
}
