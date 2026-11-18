package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The AspectJ pointcut forms Spring Security's pointcut advisors are written in (METHOD-11): which bean methods each
 * one guards, and the expressions AuthTracer can't read, which are reported rather than guessed.
 */
class PointcutFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("pointcutforms");

    @Test
    void anEllipsisInTheMiddleMatchesAnyPackagesBetween() {
        assertThat(advisors("GET /invoices")).containsExactly("Advisor services()");
        assertThat(advisor("GET /invoices", "Advisor services()").requirement().authorities())
                .containsExactly("ROLE_STAFF");
        assertThat(advisor("GET /invoices", "Advisor services()").routePattern())
                .isEqualTo("execution(* fixtures.pointcutforms..*Service.*(..))");
    }

    @Test
    void aPatternNamingAnInterfaceMatchesTheMethodsItDeclares() {
        assertThat(advisors("GET /invoices/{id}")).containsExactly("Advisor contract()");
        assertThat(advisors("GET /invoices/count")).isEmpty();
    }

    @Test
    void annotationPatternsReadTheMethodAndItsClass() {
        // Both keep the constructor's order, FIRST: Spring then takes them as the configuration registers them, in the
        // order it declares them.
        assertThat(advisors("POST /invoices/purge")).containsExactly("Advisor services()", "Advisor adminOnly()");
        assertThat(advisors("GET /archive")).containsExactly("Advisor audited()");
    }

    @Test
    void aNegationLeavesOutWhatItNames() {
        assertThat(advisors("GET /ledger")).containsExactly("Advisor ledger()");
        assertThat(advisors("GET /ledger/rates")).isEmpty();
    }

    @Test
    void eitherSideOfAnOrMatchesWithItsModifiersReturnTypeAndParameters() {
        assertThat(advisors("GET /exports/{id}")).containsExactly("Advisor lookups()");
        assertThat(advisors("GET /exports/yearly")).containsExactly("Advisor lookups()");
        // An int, not a String; package-private, not public; two longs, not one; a String, not a long; another name.
        assertThat(advisors("GET /exports/total")).isEmpty();
        assertThat(advisors("GET /exports/draft")).isEmpty();
        assertThat(advisors("GET /exports/range")).isEmpty();
        assertThat(advisors("GET /exports/by-name")).isEmpty();
        assertThat(advisors("GET /exports/all")).isEmpty();
    }

    @Test
    void anEllipsisAmongTheParametersStandsForAnyNumberOfThem() {
        assertThat(advisors("GET /statements/monthly")).containsExactly("Advisor monthEnd()");
        assertThat(advisors("GET /statements/yearly")).isEmpty();
    }

    @Test
    void theWordOperatorsAndParenthesesReadLikeTheSymbols() {
        assertThat(advisors("GET /dashboard")).containsExactly("Advisor reports()");
        assertThat(advisors("GET /charts")).containsExactly("Advisor reports()");
        assertThat(advisors("GET /dashboard/health")).isEmpty();
    }

    @Test
    void aProtectedPatternMatchesOnlyProtectedMethods() {
        assertThat(advisors("POST /drafts/open")).containsExactly("Advisor drafts()");
        assertThat(advisors("POST /drafts/close")).isEmpty();
    }

    @Test
    void anAdvisorWithoutTheInfrastructureRoleNeverRuns() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).singleElement().asString()
                .contains("support()", "ROLE_INFRASTRUCTURE");
    }

    @Test
    void aPointcutAuthTracerCantReadIsReportedWithItsExpression() {
        Map<String, String> unread = Map.ofEntries(
                Map.entry("beanNames()", "bean(*Controller)"),
                Map.entry("stringArguments()", "execution(* fixtures.pointcutforms..*(..)) && args(java.lang.String)"),
                Map.entry("annotatedMethods()", "execution(@fixtures.pointcutforms.AdminOnly * *(..))"),
                Map.entry("unclosed()", "execution(* fixtures.pointcutforms.Archive.*(..)"),
                Map.entry("singleAmpersand()",
                        "execution(* fixtures.pointcutforms.Archive.*(..)) & within(fixtures.pointcutforms..*)"),
                Map.entry("missingOperator()",
                        "(within(fixtures.pointcutforms.ledger..*) within(fixtures.pointcutforms.reports..*))"),
                Map.entry("danglingOperator()", "within(fixtures.pointcutforms.ledger..*) and"),
                Map.entry("extraParenthesis()", "execution(* fixtures.pointcutforms.Archive.*(..)))"),
                Map.entry("noParameters()", "execution(* fixtures.pointcutforms.Archive.*)"),
                Map.entry("methodReference()", "execution(* fixtures.pointcutforms.Archive#fetch(..))"),
                Map.entry("missingReturnType()", "execution(fixtures.pointcutforms.Archive.fetch(..))"),
                Map.entry("shortAnnotationName()", "@annotation(AdminOnly)"));
        List<String> opaque = graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .map(Finding::message).toList();
        unread.forEach((bean, expression) -> assertThat(opaque)
                .anySatisfy(message -> assertThat(message).contains(bean, "(" + expression + ")")));
        assertThat(graph.nodes(AuthorizationLocation.class)).extracting(AuthorizationLocation::mechanism)
                .noneMatch(mechanism -> unread.keySet().stream().anyMatch(mechanism::endsWith));
    }

    @Test
    void aPointcutThatIsNoExpressionIsReportedWithoutOne() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("annotationMatching()",
                        "uses a pointcut AuthTracer can't read; the methods it guards show no check for it"))
                .anySatisfy(message -> assertThat(message).contains("configured(java.lang.String)",
                        "uses a pointcut AuthTracer can't read; the methods it guards show no check for it"));
    }

    private List<String> advisors(String ingress) {
        return checks(ingress).stream().map(AuthorizationLocation::mechanism)
                .filter(mechanism -> mechanism.startsWith("Advisor ")).toList();
    }

    private AuthorizationLocation advisor(String ingress, String mechanism) {
        return checks(ingress).stream().filter(location -> location.mechanism().equals(mechanism)).findFirst()
                .orElseThrow();
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST).toList();
    }
}
