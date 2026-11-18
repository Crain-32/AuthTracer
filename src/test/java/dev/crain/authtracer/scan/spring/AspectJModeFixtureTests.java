package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * METHOD-14: {@code @EnableMethodSecurity(mode = AdviceMode.ASPECTJ)} hands the checks to aspects, which run only
 * where they are woven.
 */
class AspectJModeFixtureTests {

    private static final String DETAIL = "location:METHOD:fixtures.aspectj.Reports#detail():@PreAuthorize";
    private static final String FETCH = "location:METHOD:fixtures.aspectj.Archive#fetch():@PreAuthorize";
    private static final String AUDIT = "location:METHOD:fixtures.aspectj.Reports#audit():@RolesAllowed";

    @Test
    void unwovenChecksMayNeverRunAndJsr250sNeverDo() {
        ApplicationGraph graph = FixtureScans.scan("aspectj");
        assertThat(FixtureScans.path(graph, "ingress:GET /detail")).doesNotContain(DETAIL, FETCH);
        assertThat(FixtureScans.path(graph, "ingress:GET /audit")).doesNotContain(AUDIT);
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message)
                .contains("@PreAuthorize on fixtures.aspectj.Reports#detail may never run: mode = AdviceMode.ASPECTJ"
                        + " leaves it to AspectJ, and fixtures.aspectj.Reports isn't woven at compile time (an AspectJ"
                        + " load-time weaving agent may weave it)",
                        "@RolesAllowed on fixtures.aspectj.Reports#audit never runs: mode = AdviceMode.ASPECTJ has no"
                                + " aspect for it, and makes no advisor of it");
    }

    @Test
    void wovenChecksRunOnCallsOnThisButJsr250sHaveNoAspect() {
        ApplicationGraph woven = FixtureScans.scanWoven("aspectj");
        // ajc moves detail's code to an around body the aspect runs: what it calls is still reached.
        assertThat(FixtureScans.path(woven, "ingress:GET /summary")).contains(DETAIL, FETCH);
        assertThat(FixtureScans.path(woven, "ingress:GET /detail")).containsSubsequence(DETAIL, FETCH);
        // Named by the woven method, not by what ajc made of it.
        assertThat(woven.edges()).flatExtracting(Edge::via).isNotEmpty()
                .noneMatch(via -> via.contains("_aroundBody") || via.contains("$AjcClosure"));
        assertThat(FixtureScans.path(woven, "ingress:GET /audit")).doesNotContain(AUDIT);
        assertThat(woven.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.BYPASSED);
        assertThat(woven.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).noneMatch(message -> message.contains("Reports#detail"))
                .anyMatch(message -> message.contains("Reports#audit never runs"));
    }

    @Test
    void theLegacyAnnotationRegistersNoAdvisorSoUnwovenChecksMayNeverRun() {
        ApplicationGraph graph = FixtureScans.scan("aspectjlegacy");
        assertThat(FixtureScans.path(graph, "ingress:GET /balance"))
                .noneMatch(id -> id.contains("Ledger#balance()"));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).anyMatch(message -> message.startsWith(
                        "@PreAuthorize on fixtures.aspectjlegacy.Ledger#balance may never run: mode ="
                                + " AdviceMode.ASPECTJ leaves it to AspectJ"));
    }

    @Test
    void theLegacyAspectRunsWhereItIsWovenBehindTheNewOnes() {
        // ajc weaves both aspects of spring-security-aspects; the legacy one runs in the around body the new one's
        // closure calls.
        ApplicationGraph woven = FixtureScans.scanWoven("aspectjlegacy");
        assertThat(FixtureScans.path(woven, "ingress:GET /balance"))
                .contains("location:METHOD:fixtures.aspectjlegacy.Ledger#balance():@PreAuthorize");
        assertThat(woven.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED
                && finding.message().contains("Ledger#balance"));
    }

    @Test
    void loadTimeWeavingWeavesEveryCall() {
        ApplicationGraph graph = FixtureScans.scan("loadtimeweaving");
        assertThat(FixtureScans.path(graph, "ingress:GET /latest"))
                .contains("location:METHOD:fixtures.loadtimeweaving.Payslips#payslip():@PreAuthorize");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.BYPASSED
                || finding.kind() == Finding.Kind.NOT_ENFORCED);
    }
}
