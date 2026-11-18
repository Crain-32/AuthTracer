package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0091 (EXPR-05): a MethodSecurityExpressionHandler bean decides pre/post's role prefix, hierarchy and
 * factory, and a subclass may bring a root of its own.
 */
class ExpressionHandlersFixtureTests {

    @Test
    void aRootTheEvaluationContextOverrideMakesChecksRolesItselfNotAsTheHandlerIsSetUp() {
        // TeamExpressionHandler sets TEAM_ on itself, but expressions run on the TeamRoot its createEvaluationContext
        // makes: a SecurityExpressionRoot starts with ROLE_ and Spring's default factory, neither the handler's
        // prefix nor a hierarchy (7.1.1).
        ApplicationGraph graph = FixtureScans.scan("expressionhandler");
        assertThat(check(graph, "ingress:GET /rota").requirement().authorities()).containsExactly("ROLE_STAFF");
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
            assertThat(finding.message()).contains("its own AuthenticationTrustResolver");
        });
    }

    @Test
    void aRootTheOverrideSetsUpAsTheHandlerIsChecksRolesAsTheHandlerDoes() {
        ApplicationGraph graph = FixtureScans.scan("expressionhandlersetup");
        assertThat(check(graph, "ingress:GET /roster").requirement().authorities()).containsExactly("CREW_PILOT");
    }

    @Test
    void theRootAnEvaluationContextOverrideSetsDecidesTheCallsToItsMethods() {
        ApplicationGraph graph = FixtureScans.scan("expressionhandler");
        Requirement team = check(graph, "ingress:GET /teams/{team}").requirement();
        assertThat(team.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(team.decidedBy().key()).isEqualTo("fixtures.expressionhandler.TeamRoot#isMember(java.lang.String)");
        // A root method that always grants is permit-all in disguise.
        assertThat(check(graph, "ingress:GET /pager").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.OPAQUE_CONFIG);
            assertThat(finding.message()).contains("TeamExpressionHandler makes the evaluation context");
        });
    }

    @Test
    void aRootOnlyCreateSecurityExpressionRootMakesIsNeverUsedSoCallingItsMethodsDeniesEveryone() {
        ApplicationGraph graph = FixtureScans.scan("expressionhandlerroot");
        AuthorizationLocation one = check(graph, "ingress:GET /accounts/{id}");
        assertThat(one.requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(graph.findings()).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.NOT_ENFORCED);
            assertThat(finding.message()).contains("OwnerExpressionHandler", "never call");
        }).anySatisfy(finding -> {
            assertThat(finding.kind()).isEqualTo(Finding.Kind.ALWAYS_DENIED);
            assertThat(finding.message()).contains("calls isOwner(..)");
        });
    }

    @Test
    void theHandlersHierarchyAndNullPrefixApply() {
        ApplicationGraph graph = FixtureScans.scan("expressionhandlerroot");
        assertThat(check(graph, "ingress:GET /accounts").requirement().authorities())
                .containsExactlyInAnyOrder("STAFF", "ADMIN");
    }

    @Test
    void aHandlerGivenTheFactoryBeanBuildsWithIt() {
        ApplicationGraph graph = FixtureScans.scan("expressionhandlerfactory");
        assertThat(check(graph, "ingress:GET /shifts").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_STAFF", "ROLE_ADMIN");
        assertThat(graph.findings()).anySatisfy(finding -> assertThat(finding.message())
                .contains("does not set its role prefix from a constant"));
    }

    private static AuthorizationLocation check(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() == AuthorizationLocation.Scope.METHOD).findFirst().orElseThrow();
    }
}
