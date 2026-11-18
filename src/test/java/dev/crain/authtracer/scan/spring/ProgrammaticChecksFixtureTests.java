package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.DiffReport;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.mutation.MutationScans;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0066 (AUTHZ-11): checks the code makes itself with an AuthorizationManager's {@code verify(..)} or
 * {@code authorize(..)}.
 */
class ProgrammaticChecksFixtureTests {

    private static final String DOCUMENTS = "fixtures.programmaticchecks.Documents";

    private final ApplicationGraph graph = FixtureScans.scan("programmaticchecks");

    @Test
    void verifyIsAMethodCheckAtTheCallWithTheManagersRequirement() {
        AuthorizationLocation purge = check(graph, "ingress:GET /documents/purge");
        assertThat(purge.mechanism()).isEqualTo("AuthorizationManager#verify");
        assertThat(purge.scope()).isEqualTo(AuthorizationLocation.Scope.METHOD);
        assertThat(purge.phase()).isEqualTo(AuthorizationLocation.Phase.PRE);
        assertThat(purge.target().key()).isEqualTo(DOCUMENTS + "#purge()");
        assertThat(purge.target().line()).isNotNull();
        // A constant from Spring's factories, in a static field.
        assertThat(purge.requirement().authorities()).containsExactly("ROLE_ADMIN");
    }

    @Test
    void anInjectedCustomManagerIsDecidedByItsAuthorizeMethod() {
        Requirement read = check(graph, "ingress:GET /documents/{id}").requirement();
        assertThat(read.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(read.decidedBy().className()).isEqualTo("fixtures.programmaticchecks.DocumentAuthorizationManager");
    }

    @Test
    void aComposedManagerIsReadAsItsParts() {
        Requirement publish = check(graph, "ingress:GET /documents/{id}/publish").requirement();
        assertThat(publish.kind()).isEqualTo(Kind.AND);
        assertThat(publish.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.FULLY_AUTHENTICATED, Kind.ANY_AUTHORITY);
        // Spring's factories' managers have no RoleHierarchy: ADMIN > EDITOR doesn't widen them.
        assertThat(publish.operands().get(1).authorities()).containsExactly("ROLE_EDITOR", "ROLE_PUBLISHER");
    }

    @Test
    void aManagerGivenTheRoleHierarchyIsWidenedByIt() {
        assertThat(check(graph, "ingress:GET /documents/{id}/review").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_EDITOR", "ROLE_ADMIN");
    }

    @Test
    void authorizeCountsWhenItsResultDecidesAThrowOrAReturn() {
        AuthorizationLocation archive = check(graph, "ingress:GET /documents/{id}/archive");
        assertThat(archive.mechanism()).isEqualTo("AuthorizationManager#authorize");
        assertThat(archive.requirement().authorities()).containsExactly("archive:write");
        assertThat(check(graph, "ingress:GET /documents/{id}/draft").requirement().authorities())
                .containsExactly("ROLE_AUTHOR");
    }

    @Test
    void authorizeWhoseResultDeniesNothingIsAFindingNotACheck() {
        assertThat(checks(graph, "ingress:GET /documents/{id}/audit")).isEmpty();
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.UNRECOGNIZED_CHECK);
            assertThat(finding.location().key()).isEqualTo(DOCUMENTS + "#audit(fixtures.programmaticchecks.Document)");
            assertThat(finding.message()).contains("can't see the answer deny anything");
        });
    }

    @Test
    void aManagerAuthTracerCantReadIsAnOpaqueCheckWithAFinding() {
        Requirement share = check(graph, "ingress:GET /documents/{id}/share/{role}").requirement();
        assertThat(share.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(share.decidedBy()).isNull();
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
            assertThat(finding.message()).startsWith(DOCUMENTS + "#share(").contains("can't read");
        });
    }

    @Test
    void whatTheCodeReadsOfTheCallerToCheckWithAManagerIsNoHandRolledCheck() {
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.UNRECOGNIZED_CHECK
                && finding.message().startsWith("Hand-rolled"));
    }

    @Test
    void aManagerCreatedInPlaceOrComposedWithADefaultDecisionAndANegationIsRead() {
        assertThat(check(graph, "ingress:GET /drafts/{id}/edit").requirement().decidedBy().className())
                .isEqualTo("fixtures.programmaticchecks.DocumentAuthorizationManager");
        Requirement share = check(graph, "ingress:GET /drafts/{id}/share").requirement();
        assertThat(share.kind()).isEqualTo(Kind.OR);
        assertThat(share.operands().get(0).kind()).isEqualTo(Kind.NOT);
        assertThat(share.operands().get(1).decidedBy().className())
                .isEqualTo("fixtures.programmaticchecks.DraftsManager");
    }

    /**
     * Decision 0106: the custom manager's decision carries a digest of its class, so changing what it asks needs
     * review rather than passing.
     */
    @Test
    void changingACustomManagersCodeNeedsReview() {
        MutationScans.Mutated widened = MutationScans.mutate("programmaticchecks",
                "DraftsManager: hasRole(\"WRITER\") also lets in USER");
        assertThat(widened.diff().changes()).filteredOn(change -> change.endpoint().equals("GET /drafts/{id}/share"))
                .extracting(DiffReport.Change::kind).containsExactly(DiffReport.Kind.CHANGED);
        assertThat(check(graph, "ingress:GET /drafts/{id}/share").requirement().operands().get(1).code())
                .isNotBlank();
        // A manager it can't read at all: the code that builds it, where the check is made.
        assertThat(check(graph, "ingress:GET /documents/{id}/share/{role}").requirement().code()).isNotBlank();
    }

    @Test
    void aCustomManagersOwnCallsToItsDelegateAreItsDecisionNotChecksOfTheirOwn() {
        // The service asks DraftsManager, whose authorize asks its delegate: one check, decided by DraftsManager.
        assertThat(check(graph, "ingress:GET /drafts/{id}/review").requirement().decidedBy().method())
                .startsWith("authorize(");
    }

    @Test
    void anEarlyReturnFromAVoidMethodGatesWhatFollows() {
        assertThat(check(graph, "ingress:GET /drafts/{id}/delete").requirement().authorities())
                .containsExactly("ROLE_OWNER");
    }

    @Test
    void anAnswerNothingReadsIsAFinding() {
        assertThat(checks(graph, "ingress:GET /drafts/{id}/touch")).isEmpty();
        assertThat(graph.findings()).anySatisfy(finding -> assertThat(finding.location().key())
                .isEqualTo("fixtures.programmaticchecks.Drafts#touch(fixtures.programmaticchecks.Document)"));
    }

    @Test
    void aRoleFromAVariableLeavesTheManagerUnread() {
        assertThat(check(graph, "ingress:GET /drafts/{id}/tag/{team}").requirement().kind())
                .isEqualTo(Kind.EXPRESSION);
    }

    @Test
    void aCheckOnAnAsyncThreadDeniesThereWithoutTheCaller() {
        AuthorizationLocation reindex = check(graph, "ingress:GET /documents/{id}/reindex");
        assertThat(reindex.requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.ALWAYS_DENIED);
            assertThat(finding.message()).contains("AuthorizationManager#verify", "@Async",
                    "the manager finds no Authentication");
        });
    }

    @Test
    void reactiveVerifyChecksWhenItsMonoIsReturnedAndNothingWhenItIsDropped() {
        ApplicationGraph reactive = FixtureScans.scan("programmaticreactive");
        assertThat(check(reactive, "ingress:GET /reactive/restart").requirement().authorities())
                .containsExactly("ROLE_OPERATOR");
        assertThat(checks(reactive, "ingress:GET /reactive/flush")).isEmpty();
        assertThat(reactive.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.UNRECOGNIZED_CHECK);
            assertThat(finding.message()).contains("drops the Mono");
        });
    }

    private static AuthorizationLocation check(ApplicationGraph graph, String ingress) {
        List<AuthorizationLocation> checks = checks(graph, ingress);
        assertThat(checks).hasSize(1);
        return checks.getFirst();
    }

    /**
     * The checks the code makes on the path, after the request rules.
     */
    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().startsWith(ProgrammaticChecks.MECHANISM)).toList();
    }
}
