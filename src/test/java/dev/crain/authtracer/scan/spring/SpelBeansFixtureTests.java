package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0064 (EXPR-03, OAUTH-04): SpEL bean references resolved to the bean's method.
 */
class SpelBeansFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("spelbeans");

    @Test
    void aBeanMethodIsCustomDecidedByThatMethod() {
        Requirement document = preAuthorize("GET /documents/{id}").requirement();
        assertThat(document.kind()).isEqualTo(Kind.AND);
        Requirement bean = document.operands().getFirst();
        assertThat(bean.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(bean.expression()).isEqualTo("@authz.canRead(#id,#root)");
        assertThat(bean.decidedBy()).isEqualTo(CodeRef.ofMethod("fixtures.spelbeans.AuthorizationLogic",
                "canRead(java.lang.Long,org.springframework.security.access.expression.method"
                        + ".MethodSecurityExpressionOperations)"));
        assertThat(document.operands().get(1).authorities()).containsExactly("ROLE_USER");
    }

    @Test
    void codeThatCantBeReducedIsReportedOnceForTheMethodThatDecides() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .filteredOn(finding -> finding.location().className().equals("fixtures.spelbeans.AuthorizationLogic"))
                .extracting(Finding::message).singleElement().asString()
                .contains("AuthorizationLogic#canRead", "@PreAuthorize", "can't reduce");
    }

    @Test
    void theOAuth2FactorysScopesAreScopeAuthorities() {
        Requirement messages = preAuthorize("GET /messages").requirement();
        assertThat(messages.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(messages.authorities()).containsExactly("SCOPE_message:read");
        assertThat(messages.expression()).isEqualTo("@oauth2.hasScope('message:read')");
        assertThat(messages.decidedBy().method()).isEqualTo("oauth2()");
        assertThat(preAuthorize("GET /legacy/messages").requirement().authorities()).containsExactly("PERM_messages");
    }

    @Test
    void aFactoryWrappingTheMultiFactorFactoryAlsoNeedsItsFactors() {
        Requirement admin = preAuthorize("GET /admin/messages").requirement();
        assertThat(admin.kind()).isEqualTo(Kind.AND);
        assertThat(admin.operands()).extracting(Requirement::authorities).containsExactly(
                new java.util.TreeSet<>(java.util.List.of("SCOPE_admin", "SCOPE_message:admin")),
                new java.util.TreeSet<>(java.util.List.of("FACTOR_OTT", "FACTOR_PASSWORD")));
    }

    @Test
    void aBeanNothingDefinesIsReported() {
        assertThat(preAuthorize("GET /archive").requirement()).isEqualTo(Requirement.expression("@archivist.mayRead()"));
        assertThat(graph.findings()).extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("@archivist", "no bean"));
    }

    private AuthorizationLocation preAuthorize(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals("@PreAuthorize")).findFirst().orElseThrow();
    }
}
