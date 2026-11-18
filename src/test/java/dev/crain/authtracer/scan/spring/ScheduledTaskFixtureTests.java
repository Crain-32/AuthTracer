package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0046: {@code @Scheduled} methods as entry points nobody calls.
 */
class ScheduledTaskFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("scheduled");

    @Test
    void scheduledMethodsAreEntryPointsWithTheirCalls() {
        assertThat(graph.nodes(Ingress.class)).filteredOn(ScheduledTasks::isScheduled).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:SCHEDULED Reports.nightly", "ingress:SCHEDULED Reports.heartbeat");
        // The job's call to another service is on its path, so the linker sees it.
        assertThat(path(graph, "ingress:SCHEDULED Reports.nightly")).map(id -> graph.node(id).orElseThrow())
                .filteredOn(Egress.class::isInstance).map(Egress.class::cast).singleElement()
                .satisfies(egress -> assertThat(egress.uriTemplate()).isEqualTo("/reports/daily"));
    }

    @Test
    void aMethodCheckATaskReachesHasNoCaller() {
        assertThat(path(graph, "ingress:SCHEDULED Reports.nightly")).map(id -> graph.node(id).orElseThrow())
                .filteredOn(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .singleElement().satisfies(check -> {
                    assertThat(check.mechanism()).isEqualTo("@PreAuthorize (no caller)");
                    assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.DENY_ALL);
                });
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .singleElement().satisfies(finding -> assertThat(finding.message())
                        .contains("SCHEDULED Reports.nightly runs", "Payroll#close"));
    }

    @Test
    void aCheckCalledTwiceIsReportedOnceAndAnAsyncOneKeepsItsThread() {
        ApplicationGraph handoff = FixtureScans.scan("scheduledhandoff");
        assertThat(path(handoff, "ingress:SCHEDULED MonthEnd.close")).map(id -> handoff.node(id).orElseThrow())
                .filteredOn(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .extracting(check -> check.mechanism() + " " + check.target().className().replaceAll(".*\\.", "")
                        + " " + check.requirement().kind())
                .containsOnly("@PreAuthorize (no caller) Ledgers DENY_ALL", "@PreAuthorize (@Async) Archive DENY_ALL");
        // The HTTP service client's method, which has no body, is walked past.
        assertThat(path(handoff, "ingress:SCHEDULED MonthEnd.close")).map(id -> handoff.node(id).orElseThrow())
                .filteredOn(Egress.class::isInstance).map(Egress.class::cast).singleElement()
                .satisfies(egress -> assertThat(egress.uriTemplate()).isEqualTo("/statements/{month}"));
        assertThat(handoff.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).hasSize(2)
                .anySatisfy(message -> assertThat(message).contains("Ledgers#close", "has no caller"))
                .anySatisfy(message -> assertThat(message).contains("Archive#store", "@Async thread")
                        // Decision 0093: a task has no caller to leave behind.
                        .contains("and SCHEDULED MonthEnd.close has no caller, so the thread has no SecurityContext",
                                "unless the code sets a SecurityContext there, or sets one before handing the work"
                                        + " over and the executor carries it over")
                        .doesNotContain("caller's SecurityContext"));
    }

    @Test
    void aTaskOnTwoSchedulesIsOneEntryPoint() {
        assertThat(FixtureScans.scan("schedules").nodes(Ingress.class)).filteredOn(ScheduledTasks::isScheduled)
                .extracting(Ingress::id).containsExactly("ingress:SCHEDULED Backups.snapshot");
    }

    @Test
    void withoutEnableSchedulingNothingRuns() {
        assertThat(FixtureScans.scan("messaging").nodes(Ingress.class)).noneMatch(ScheduledTasks::isScheduled);
    }
}
