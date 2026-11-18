package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0097: the method checks the XML namespace sets up without annotations: {@code <protect-pointcut>} and a
 * bean's {@code <intercept-methods>}.
 */
class XmlMethodsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("xmlmethods");

    @Test
    void theFirstProtectPointcutThatMatchesDecidesBeforeTheAnnotations() {
        List<AuthorizationLocation> post = methodChecks(graph, "POST /ledger");
        assertThat(post).extracting(AuthorizationLocation::mechanism).containsExactly("protect-pointcut",
                "@PreAuthorize");
        assertThat(post.getFirst().requirement().authorities()).containsExactly("ROLE_ACCOUNTANT");
        // "and not" is AspectJ's "&& !"; the next pointcut matches the method the first leaves out.
        assertThat(methodChecks(graph, "GET /ledger/balance")).singleElement().satisfies(check ->
                assertThat(check.requirement().authorities()).containsExactly("ROLE_AUDITOR"));
    }

    @Test
    void aPointcutAuthTracerCantReadIsAFinding() {
        assertThat(findings(Finding.Kind.OPAQUE_CONFIG)).anySatisfy(message -> assertThat(message)
                .contains("args(java.lang.String)"));
    }

    @Test
    void interceptMethodsAsksEveryMethodForTheFirstProtectItsNameMatchesOrDenies() {
        assertThat(methodChecks(graph, "GET /reports")).singleElement().satisfies(check -> {
            assertThat(check.mechanism()).isEqualTo("intercept-methods");
            assertThat(check.requirement().authorities()).containsExactly("ROLE_VIEWER");
        });
        assertThat(methodChecks(graph, "GET /reports/summary")).singleElement().satisfies(check ->
                assertThat(check.requirement().authorities()).containsExactly("ROLE_MANAGER"));
        assertThat(methodChecks(graph, "GET /reports/count")).singleElement().satisfies(check ->
                assertThat(check.requirement().kind()).isEqualTo(Kind.DENY_ALL));
        // A qualified name never matches in 7.1.1, so the method it names is denied too.
        assertThat(methodChecks(graph, "POST /reports/purge")).singleElement().satisfies(check ->
                assertThat(check.requirement().kind()).isEqualTo(Kind.DENY_ALL));
        assertThat(findings(Finding.Kind.ALWAYS_DENIED)).anySatisfy(message -> assertThat(message)
                .contains("fixtures.xmlmethods.ReportService.purge").contains("never matches"));
    }

    @Test
    void aManagerBeanDecidesEveryProtectedMethod() {
        assertThat(methodChecks(graph, "POST /archive")).singleElement().satisfies(check -> {
            assertThat(check.requirement().authorities()).containsExactly("ROLE_ARCHIVIST");
            assertThat(check.requirement().decidedBy().className()).isEqualTo("fixtures.xmlmethods.ArchiveManager");
        });
        assertThat(methodChecks(graph, "POST /vault")).singleElement().satisfies(check ->
                assertThat(check.requirement().expression()).isEqualTo("authorization-manager-ref(vaultManager)"));
        assertThat(findings(Finding.Kind.OPAQUE_CONFIG)).anySatisfy(message -> assertThat(message)
                .contains("vaultManager"));
    }

    @Test
    void theLegacyInterceptorTakesTheMostSpecificNameAndLetsTheRestThrough() {
        assertThat(methodChecks(graph, "GET /notes")).singleElement().satisfies(check ->
                assertThat(check.requirement().authorities()).containsExactly("ROLE_READER"));
        assertThat(methodChecks(graph, "GET /notes/secret")).singleElement().satisfies(check ->
                assertThat(check.requirement().authorities()).containsExactly("ROLE_KEEPER"));
        assertThat(methodChecks(graph, "POST /notes")).isEmpty();
    }

    @Test
    void globalMethodSecuritysPointcutsDecideOnlyWhereNoEnabledAnnotationDoes() {
        ApplicationGraph global = FixtureScans.scan("xmlglobalmethods");
        assertThat(methodChecks(global, "POST /payroll/run")).singleElement().satisfies(check -> {
            assertThat(check.mechanism()).isEqualTo("protect-pointcut (global-method-security)");
            // Its attributes keep their spaces: " ROLE_HR" is no role attribute.
            assertThat(check.requirement().authorities()).containsExactly("ROLE_PAYROLL");
        });
        assertThat(methodChecks(global, "GET /payroll/preview")).extracting(AuthorizationLocation::mechanism)
                .containsExactly("@PreAuthorize");
        // @Secured isn't enabled, so it is no source: the pointcut decides.
        assertThat(methodChecks(global, "GET /payroll/audit")).extracting(AuthorizationLocation::mechanism)
                .containsExactly("protect-pointcut (global-method-security)");
    }

    private List<String> findings(Finding.Kind kind) {
        return graph.findings().stream().filter(finding -> finding.kind() == kind).map(Finding::message).toList();
    }

    private static List<AuthorizationLocation> methodChecks(ApplicationGraph graph, String ingress) {
        return FixtureScans.path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() == AuthorizationLocation.Scope.METHOD).toList();
    }
}
