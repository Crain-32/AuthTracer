package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * FIELD-06 and FIELD-07: the advisors Spring Security's proxy factory applies to returned objects, and the types an
 * AOT hint registrar names.
 */
class ProxyAdvisorsFixtureTests {

    private static final String ACCOUNT = "fixtures.proxyadvisors.Account#";
    private static final String AUDIT = ":advisor:fixtures.proxyadvisors.ProxyAdvisorsConfig#auditAccounts()";
    private static final String EMAIL_AUDIT = "location:FIELD:" + ACCOUNT + "getEmail()" + AUDIT;
    private static final String EMAIL_MASKING = "location:FIELD:" + ACCOUNT + "getEmail():advisor:"
            + "fixtures.proxyadvisors.MaskingAdvisor";

    private final ApplicationGraph graph = FixtureScans.scan("proxyadvisors");

    @Test
    void aPointcutAdvisorGuardsTheReturnedObjectsItMatches() {
        assertThat(path(graph, "ingress:GET /accounts/{id}")).contains(EMAIL_AUDIT);
        assertThat(location(EMAIL_AUDIT).requirement().authorities()).containsExactly("ROLE_AUDITOR");
        assertThat(location(EMAIL_AUDIT).field()).isEqualTo("email");
        // A method that isn't a getter: a method check, on the proxy only.
        assertThat(path(graph, "ingress:GET /accounts/{id}/close"))
                .containsExactly("location:METHOD:" + ACCOUNT + "close()" + AUDIT);
    }

    @Test
    void anAdvisorOfTheApplicationsOwnIsACustomCheckOnTheReturnedObjectsItsPointcutMatches() {
        assertThat(path(graph, "ingress:GET /accounts/{id}")).contains(EMAIL_MASKING);
        AuthorizationLocation masking = location(EMAIL_MASKING);
        assertThat(masking.mechanism()).isEqualTo("Advisor MaskingAdvisor");
        assertThat(masking.requirement().withCode(null))
                .isEqualTo(Requirement.expression("custom AuthorizationAdvisor MaskingAdvisor"));
        assertThat(masking.routePattern()).isEqualTo("@annotation(fixtures.proxyadvisors.Masked)");
        // Without the infrastructure role, nothing applies it to beans.
        assertThat(path(graph, "ingress:GET /secret")).isEmpty();
        assertThat(messages(Finding.Kind.OPAQUE_CONFIG))
                .anySatisfy(message -> assertThat(message).startsWith("The AuthorizationAdvisor bean"
                        + " fixtures.proxyadvisors.MaskingAdvisor runs advice of its own on the objects"
                        + " AuthorizationProxyFactory proxies").contains("shows there as a custom check"))
                .anySatisfy(message -> assertThat(message).startsWith("The AuthorizationAdvisor bean"
                        + " fixtures.proxyadvisors.Unread").contains("doesn't read its pointcut"));
    }

    @Test
    void anAdvisorWithTheInfrastructureRoleGuardsBeansToo() {
        assertThat(path(graph, "ingress:GET /ledger")).containsExactly("location:METHOD:"
                + "fixtures.proxyadvisors.Ledger#entries():advisor:fixtures.proxyadvisors.AuditingAdvisor");
        assertThat(messages(Finding.Kind.OPAQUE_CONFIG)).anySatisfy(message -> assertThat(message)
                .contains("AuditingAdvisor runs advice of its own on the beans and the objects")
                .contains("(@within(fixtures.proxyadvisors.Audited))"));
    }

    @Test
    void anAdvisorNothingAppliesNeverRuns() {
        assertThat(FixtureScans.scan("proxyadvisorsoff").findings()).extracting(Finding::message)
                .containsExactly("The AuthorizationAdvisor bean fixtures.proxyadvisorsoff.Lone never runs: nothing"
                        + " auto-proxies beans and there is no AuthorizationProxyFactory (no @EnableMethodSecurity)");
    }

    @Test
    void aCustomizerThatReplacesTheFactorysAdvisorsLeavesOnlyThoseItSets() {
        // 7.1.1 AuthorizationProxyConfiguration hands the factory every AuthorizationAdvisor bean, then the
        // customizers; setAdvisors(..) replaces them all.
        ApplicationGraph customized = FixtureScans.scan("proxyadvisorscustomized");
        assertThat(path(customized, "ingress:GET /accounts/{id}/close")).isEmpty();
        // @PreAuthorize as the interceptor setAdvisors lists reads it: Spring's defaults.
        assertThat(path(customized, "ingress:GET /accounts/{id}")).containsExactly(
                "location:FIELD:fixtures.proxyadvisorscustomized.Account#getEmail():@PreAuthorize:built-factory");
        assertThat(customized.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).startsWith("A lambda in"
                        + " fixtures.proxyadvisorscustomized.ProxyAdvisorsCustomizedConfig#preAuthorizeOnly()")
                        .contains("replaces the advisors AuthorizationProxyFactory applies", "only @PreAuthorize"))
                .anySatisfy(message -> assertThat(message).contains("ProxyAdvisorsCustomizedConfig#withLogging(")
                        .contains("adds an advisor"));
        assertThat(customized.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.BYPASSED)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("Advisor auditAccounts() on",
                        "Account#close()", "Spring Security's proxy factory, which a customizer sets to apply only"
                                + " @PreAuthorize"));
    }

    @Test
    void aTypeAHintRegistrarNamesIsProxied() {
        AuthorizationLocation balance = location("location:FIELD:fixtures.proxyadvisors.Statement#getBalance()"
                + ":@PreAuthorize");
        assertThat(balance.field()).isEqualTo("balance");
        assertThat(messages(Finding.Kind.NOT_ENFORCED)).noneMatch(message -> message.contains("Statement"));
    }

    private List<String> messages(Finding.Kind kind) {
        return graph.findings().stream().filter(finding -> finding.kind() == kind).map(Finding::message).toList();
    }

    private AuthorizationLocation location(String id) {
        return (AuthorizationLocation) graph.node(id).orElseThrow();
    }
}
