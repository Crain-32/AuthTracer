package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.AuthorizationLocation.Phase;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * The advisor beans Spring Security's method security is configured with (METHOD-11, METHOD-12, AUTHZ-02): the
 * interceptors that turn an annotation on, the managers a pointcut advisor is built with, and where
 * {@code setOrder} places an advisor among Spring's own interceptors.
 */
class AdvisorShapesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("advisorshapes");

    @Test
    void theFilterInterceptorsTurnTheFilterAnnotationsOn() {
        AuthorizationLocation preFilter = check("POST /payroll/timesheets", "@PreFilter");
        assertThat(preFilter.denial().kind()).isEqualTo(AuthorizationLocation.Denial.Kind.FILTER);
        assertThat(preFilter.requirement().expression()).isEqualTo("filterObject.startsWith(authentication.name)");
        assertThat(check("GET /payroll", "@PostFilter").phase()).isEqualTo(Phase.POST);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED).isEmpty();
    }

    @Test
    void anAnnotationsOwnManagerKeepsItsMeaningWhateverItIsGiven() {
        assertThat(check("POST /payroll/approve", "@PreAuthorize").requirement().authorities())
                .containsExactly("ROLE_MANAGER");
        assertThat(check("GET /payroll/report", "@PostAuthorize").requirement().expression())
                .contains("returnObject != null");
        assertThat(check("GET /payroll/audit", "@RolesAllowed").requirement().authorities())
                .containsExactly("ROLE_AUDITOR");
        // The JSR-250 interceptor reads @DenyAll and @PermitAll too.
        assertThat(check("GET /payroll/archive", "@DenyAll").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(check("GET /payroll/holidays", "@PermitAll").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void aLambdaManagerDecidesInsteadOfTheAnnotation() {
        Requirement secured = check("POST /payroll/approve", "@Secured").requirement();
        assertThat(secured.expression()).isEqualTo("custom AuthorizationManager lambda$secured$0");
        assertThat(secured.decidedBy().className()).isEqualTo("fixtures.advisorshapes.AnnotationAdvisorsConfig");
    }

    @Test
    void eachManagerFactoryBecomesItsRequirement() {
        assertThat(advisor("any-role").authorities()).containsExactly("ROLE_MANAGER", "ROLE_TELLER");
        assertThat(advisor("any-role").kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(advisor("prefixed-role").authorities()).containsExactly("GROUP_MANAGER", "GROUP_TELLER");
        assertThat(advisor("all-roles").kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(advisor("all-roles").authorities()).containsExactly("ROLE_AUDITOR", "ROLE_TELLER");
        assertThat(advisor("prefixed-authorities").kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(advisor("prefixed-authorities").authorities()).containsExactly("GROUP_AUDITOR", "GROUP_TELLER");
        assertThat(advisor("all-authorities").authorities()).containsExactly("SCOPE_vault.read", "SCOPE_vault.write");
        assertThat(advisor("any-authority").authorities()).containsExactly("SCOPE_vault.admin", "SCOPE_vault.read");
        assertThat(advisor("signed-in").kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(advisor("fully").kind()).isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(advisor("remembered").kind()).isEqualTo(Kind.REMEMBER_ME);
        assertThat(advisor("anonymous")).isEqualTo(Requirement.anonymous());
        assertThat(advisor("open").kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(advisor("closed").kind()).isEqualTo(Kind.DENY_ALL);
    }

    @Test
    void aComposedManagerIsReadAndARoleTheConfigurationSuppliesIsAnOpaqueManager() {
        Requirement composed = advisor("composed");
        assertThat(composed.kind()).isEqualTo(Kind.AND);
        assertThat(composed.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.FULLY_AUTHENTICATED);
        assertThat(composed.operands().getFirst().authorities()).containsExactly("ROLE_TELLER");
        assertThat(advisor("configured").withCode(null)).isEqualTo(Requirement.expression("AuthorizationManager"));
    }

    @Test
    void anAdvisorsOrderPlacesItAmongSpringsInterceptors() {
        assertThat(checks("POST /payroll/approve")).extracting(AuthorizationLocation::mechanism).containsExactly(
                "Advisor first()", "Advisor withPreFilter()", "@PreAuthorize", "Advisor afterPreAuthorize()",
                "Advisor between()", "Advisor beforeSecured()", "@Secured", "Advisor withJsr250()");
    }

    @Test
    void afterAdvisorsDecideOnTheResultInnermostFirst() {
        List<AuthorizationLocation> report = checks("GET /payroll/report");
        assertThat(report).extracting(AuthorizationLocation::mechanism).containsExactly("Advisor last()",
                "Advisor withPostFilter()", "Advisor afterPostAuthorize()", "@PostAuthorize",
                "Advisor withSecureResult()", "Advisor unordered()");
        assertThat(report).allSatisfy(location -> assertThat(location.phase()).isEqualTo(Phase.POST));
    }

    @Test
    void aReactivePostAdvisorDecidesBeforePostAuthorize() {
        ApplicationGraph reactive = FixtureScans.scan("reactiveadvisors");
        List<AuthorizationLocation> balance = path(reactive, "ingress:GET /balance").stream()
                .map(id -> reactive.node(id).orElseThrow()).filter(AuthorizationLocation.class::isInstance)
                .map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST).toList();
        assertThat(balance).extracting(AuthorizationLocation::mechanism)
                .containsExactly("Advisor auditBalance()", "@PostAuthorize");
        assertThat(balance.getFirst().requirement().authorities()).containsExactly("SCOPE_accounts.read");
    }

    private Requirement advisor(String vault) {
        List<AuthorizationLocation> checks = checks("GET /vault/" + vault);
        assertThat(checks).singleElement().extracting(AuthorizationLocation::mechanism).asString()
                .startsWith("Advisor ");
        return checks.getFirst().requirement();
    }

    private AuthorizationLocation check(String ingress, String mechanism) {
        return checks(ingress).stream().filter(location -> location.mechanism().equals(mechanism)).findFirst()
                .orElseThrow();
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST).toList();
    }
}
