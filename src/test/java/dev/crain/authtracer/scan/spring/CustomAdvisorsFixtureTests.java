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
 * FIELD-06 (decision 0077): an application's own AuthorizationAdvisor beans in a Boot application without method
 * security. Which beans they guard depends on the auto-proxy creator Boot picks: AspectJ's, which applies every
 * advisor, when AspectJ is on the classpath; else the infrastructure one, which applies those with the infrastructure
 * role.
 */
class CustomAdvisorsFixtureTests {

    private static final String PACKAGE = "fixtures.customadvisors.";
    private static final String DEFAULT_CHAIN = "location:HTTP_REQUEST:spring-boot-default:anyRequest";
    private static final String PAYROLL = "location:METHOD:" + PACKAGE + "Payroll#run():advisor:" + PACKAGE
            + "PayrollAdvisor";
    private static final String LEDGER = "location:METHOD:" + PACKAGE + "Ledger#entries():advisor:" + PACKAGE
            + "AuditAdvisor";
    private static final String EXPORT = "location:METHOD:" + PACKAGE + "Reports#export():advisor:" + PACKAGE
            + "ExportAdvisor";

    private final ApplicationGraph graph = FixtureScans.scan("customadvisors");

    @Test
    void withAspectJEveryAdvisorGuardsTheBeansItsPointcutMatches() {
        assertThat(path(graph, "ingress:GET /payroll")).containsExactly(DEFAULT_CHAIN, PAYROLL);
        AuthorizationLocation payroll = (AuthorizationLocation) graph.node(PAYROLL).orElseThrow();
        assertThat(payroll.mechanism()).isEqualTo("Advisor PayrollAdvisor");
        // Decision 0106: with a digest of the advisor's code.
        assertThat(payroll.requirement().code()).isNotBlank();
        assertThat(payroll.requirement().withCode(null))
                .isEqualTo(Requirement.expression("custom AuthorizationAdvisor PayrollAdvisor"));
        assertThat(payroll.routePattern()).isEqualTo("execution(* fixtures.customadvisors.Payroll.*(..))");
        assertThat(path(graph, "ingress:GET /ledger")).containsExactly(DEFAULT_CHAIN, LEDGER);
        assertThat(((AuthorizationLocation) graph.node(LEDGER).orElseThrow()).routePattern())
                .isEqualTo("@within(fixtures.customadvisors.Audited)");
        assertThat(path(graph, "ingress:GET /reports/export")).containsExactly(DEFAULT_CHAIN, EXPORT);
        assertThat(((AuthorizationLocation) graph.node(EXPORT).orElseThrow()).routePattern())
                .isEqualTo("@annotation(fixtures.customadvisors.Exported)");
        assertThat(path(graph, "ingress:GET /reports/summary")).containsExactly(DEFAULT_CHAIN);
    }

    @Test
    void eachAdvisorIsAFindingThatSaysWhatItRunsOn() {
        assertThat(messages(graph, Finding.Kind.OPAQUE_CONFIG))
                .contains("The AuthorizationAdvisor bean fixtures.customadvisors.PayrollAdvisor runs advice of its"
                        + " own on the beans that its pointcut matches (execution(* fixtures.customadvisors.Payroll"
                        + ".*(..))); AuthTracer doesn't read what it decides, so it shows there as a custom check")
                .contains("The AuthorizationAdvisor bean fixtures.customadvisors.ConfiguredAdvisor runs advice of"
                        + " its own on the beans that its pointcut matches; AuthTracer doesn't read its pointcut or"
                        + " what it decides, so the methods it guards show no check for it")
                .contains("The AuthorizationAdvisor bean fixtures.customadvisors.BeanNameAdvisor runs advice of"
                        + " its own on the beans that its pointcut matches (bean(payroll), which AuthTracer can't"
                        + " read); AuthTracer doesn't read its pointcut or what it decides, so the methods it guards"
                        + " show no check for it");
    }

    @Test
    void withoutAspectJOnlyTheInfrastructureAdvisorsGuardBeans() {
        ApplicationGraph infrastructure = FixtureScans.scanWithout("customadvisors", "aspectjweaver");
        // The role on the class, and on the bean method that creates it behind its interface.
        assertThat(path(infrastructure, "ingress:GET /ledger")).containsExactly(DEFAULT_CHAIN, LEDGER);
        assertThat(path(infrastructure, "ingress:GET /reports/export")).containsExactly(DEFAULT_CHAIN, EXPORT);
        assertThat(path(infrastructure, "ingress:GET /payroll")).containsExactly(DEFAULT_CHAIN);
        // A supporting role isn't the infrastructure one.
        assertThat(messages(infrastructure, Finding.Kind.NOT_ENFORCED)).containsExactlyInAnyOrder(
                "The AuthorizationAdvisor bean fixtures.customadvisors.PayrollAdvisor never runs: nothing"
                        + " auto-proxies beans and there is no AuthorizationProxyFactory (no @EnableMethodSecurity)",
                "The AuthorizationAdvisor bean fixtures.customadvisors.ConfiguredAdvisor never runs: nothing"
                        + " auto-proxies beans and there is no AuthorizationProxyFactory (no @EnableMethodSecurity)",
                "The AuthorizationAdvisor bean fixtures.customadvisors.BeanNameAdvisor never runs: nothing"
                        + " auto-proxies beans and there is no AuthorizationProxyFactory (no @EnableMethodSecurity)");
    }

    private static List<String> messages(ApplicationGraph graph, Finding.Kind kind) {
        return graph.findings().stream().filter(finding -> finding.kind() == kind).map(Finding::message).toList();
    }
}
