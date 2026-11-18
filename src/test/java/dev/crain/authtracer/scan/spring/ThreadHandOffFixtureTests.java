package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0084: Reactor schedulers, callers that wait for the other thread, {@code @Async("name")} executors, and
 * the holder strategies that carry the SecurityContext.
 */
class ThreadHandOffFixtureTests {

    private static final String CHECK = "@PreAuthorize";
    private static final String OTHER_THREAD = "@PreAuthorize (other thread)";
    private static final String WAITED = "@PreAuthorize (other thread, waited for)";

    @Test
    void workAReactorSchedulerRunsHasNoThreadLocalContext() {
        ApplicationGraph graph = FixtureScans.scan("threadhopsreactor");
        // Blocking on the pipeline (or one zipped with it), or returning it to Spring MVC, gets its failure.
        for (String ingress : List.of("ingress:GET /blocked", "ingress:GET /returned", "ingress:GET /published",
                "ingress:GET /zipped")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(WAITED).doesNotContain(CHECK, OTHER_THREAD);
            assertThat(requirement(graph, ingress)).as(ingress).contains("denyAll");
        }
        // Subscribing and going on, or recovering from the error, doesn't.
        for (String ingress : List.of("ingress:POST /fired", "ingress:GET /recovered")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(OTHER_THREAD).doesNotContain(CHECK, WAITED);
            assertThat(requirement(graph, ingress)).as(ingress).doesNotContain("denyAll");
        }
        assertThat(checks(graph, "ingress:GET /blocked")).filteredOn(check -> check.mechanism().equals(WAITED))
                .singleElement()
                .satisfies(check -> assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.DENY_ALL));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message).contains("On GET /blocked",
                        "the thread Mono.subscribeOn hands it to", "spring.reactor.context-propagation=auto",
                        "ReportController#blocked() waits for it, so the request fails with it"));
    }

    @Test
    void workBeforePublishOnOrOnTheImmediateSchedulerStaysOnTheCallersThread() {
        ApplicationGraph graph = FixtureScans.scan("threadhopsreactor");
        for (String ingress : List.of("ingress:GET /before", "ingress:GET /immediate")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(CHECK).doesNotContain(OTHER_THREAD, WAITED);
            assertThat(requirement(graph, ingress)).as(ingress).contains("ROLE_ADMIN");
        }
    }

    @Test
    void automaticContextPropagationOrACopyingScheduleHookCarriesTheContextToTheScheduler() {
        // The property, the application turning it on, and a schedule hook that copies the context.
        for (String fixture : List.of("threadhopsreactorauto", "threadhopsreactorpropagation", "threadhopsreactorhook")) {
            assertThat(mechanisms(FixtureScans.scan(fixture), "ingress:GET /blocked")).as(fixture).contains(CHECK)
                    .doesNotContain(OTHER_THREAD, WAITED);
        }
    }

    @Test
    void aCallerThatWaitsForTheFutureFailsWithIt() {
        ApplicationGraph graph = FixtureScans.scan("threadhopswaited");
        for (String ingress : List.of("ingress:GET /joined", "ingress:GET /returned", "ingress:GET /got",
                "ingress:GET /chained", "ingress:GET /all")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(WAITED).doesNotContain(CHECK, OTHER_THREAD);
            assertThat(requirement(graph, ingress)).as(ingress).contains("denyAll");
        }
    }

    @Test
    void aFutureReturnedByTheMethodThatStartedItIsWaitedForByItsCaller() {
        ApplicationGraph graph = FixtureScans.scan("threadhopswaited");
        for (String ingress : List.of("ingress:GET /loaded", "ingress:GET /passed")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(WAITED).doesNotContain(CHECK, OTHER_THREAD);
        }
        assertThat(graph.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("On GET /loaded", "ReportController#loaded() waits for it"));
        assertThat(mechanisms(graph, "ingress:POST /started")).contains(OTHER_THREAD).doesNotContain(WAITED);
    }

    @Test
    void aCallerThatCatchesOrRecoversFromTheFailureOrDoesntWaitGoesOn() {
        ApplicationGraph graph = FixtureScans.scan("threadhopswaited");
        for (String ingress : List.of("ingress:GET /caught", "ingress:GET /recovered", "ingress:POST /submitted")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(OTHER_THREAD).doesNotContain(CHECK, WAITED);
            assertThat(requirement(graph, ingress)).as(ingress).doesNotContain("denyAll");
        }
    }

    @Test
    void anAsyncMethodRunsOnTheExecutorItNames() {
        ApplicationGraph graph = FixtureScans.scan("asyncexecutors");
        // Plain executors (one named by a property, one by its @Bean name), and those whose decorator copies
        // something else (set on it, on Boot's builder, or handed to it when the application has no decorator that
        // copies the context) don't carry it.
        for (String ingress : List.of("ingress:POST /plain", "ingress:POST /traced", "ingress:POST /configured",
                "ingress:POST /reporting", "ingress:POST /builder", "ingress:POST /given")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains("@PreAuthorize (@Async)")
                    .doesNotContain(CHECK);
        }
        // Spring Security's delegating executor (one by its @Qualifier) and a decorator that copies the context do.
        for (String ingress : List.of("ingress:POST /secured", "ingress:POST /copying", "ingress:POST /audited")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(CHECK)
                    .doesNotContain("@PreAuthorize (@Async)");
        }
    }

    @Test
    void theApplicationsDecoratorBeanReachesTheExecutorsBuiltWithIt() {
        ApplicationGraph graph = FixtureScans.scan("asyncexecutorsdecorated");
        // Boot's builder applies it, a bean method can be handed it, and an executor that isn't the application's
        // keeps the application-wide reading.
        for (String ingress : List.of("ingress:POST /pooled", "ingress:POST /given", "ingress:POST /elsewhere")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(CHECK)
                    .doesNotContain("@PreAuthorize (@Async)");
        }
        assertThat(mechanisms(graph, "ingress:POST /plain")).contains("@PreAuthorize (@Async)").doesNotContain(CHECK);
    }

    @Test
    void aCallerThatWaitsForAnAsyncMethodsFutureFailsWithIt() {
        ApplicationGraph graph = FixtureScans.scan("asyncexecutors");
        for (String ingress : List.of("ingress:GET /built", "ingress:GET /handed")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains("@PreAuthorize (@Async, waited for)")
                    .doesNotContain(CHECK, "@PreAuthorize (@Async)");
            assertThat(requirement(graph, ingress)).as(ingress).contains("denyAll");
        }
    }

    @Test
    void anInheritableHolderStrategyReachesANewThreadAndAnExecutorsThreads() {
        ApplicationGraph graph = FixtureScans.scan("threadhopsholderstrategy");
        assertThat(mechanisms(graph, "ingress:POST /thread")).contains(CHECK).doesNotContain(OTHER_THREAD);
        assertThat(mechanisms(graph, "ingress:POST /refresh")).contains(CHECK).doesNotContain("@PreAuthorize (@Async)");
    }

    @Test
    void aCallerWaitsOnFuturesItKeepsAndInLambdasItRunsInPlace() {
        ApplicationGraph graph = FixtureScans.scan("threadhopswaitedforms");
        // Decision 0099: in a collection, a field (also one the next call waits on), a lambda over them or one
        // that captures one.
        for (String ingress : List.of("ingress:GET /collected", "ingress:GET /streamed", "ingress:GET /each",
                "ingress:GET /captured", "ingress:GET /fallback", "ingress:GET /kept", "ingress:GET /batched",
                "ingress:GET /drained")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(WAITED).doesNotContain(CHECK, OTHER_THREAD);
            assertThat(requirement(graph, ingress)).as(ingress).contains("denyAll");
        }
        assertThat(graph.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("On GET /batched", "Batch#await() waits for it"));
        // Kept and never waited for, or waited for on another thread.
        for (String ingress : List.of("ingress:POST /queued", "ingress:POST /forgotten", "ingress:POST /elsewhere")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(OTHER_THREAD).doesNotContain(CHECK, WAITED);
        }
    }

    @Test
    void aPipelineAnotherMethodSchedulesRunsOnTheScheduler() {
        ApplicationGraph graph = FixtureScans.scan("threadhopswaitedforms");
        // Decision 0099: subscribed on by the caller it is returned to, built on one another method subscribes on,
        // and passed to a method that subscribes it.
        for (String ingress : List.of("ingress:GET /offloaded", "ingress:GET /mapped", "ingress:GET /handed")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(WAITED).doesNotContain(CHECK, OTHER_THREAD);
        }
        assertThat(graph.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("On GET /offloaded", "Mono.subscribeOn"));
        // Nothing schedules it, here or where it is passed or returned.
        for (String ingress : List.of("ingress:GET /inline", "ingress:POST /dropped")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains(CHECK).doesNotContain(OTHER_THREAD, WAITED);
        }
    }

    @Test
    void aThreadLocalStrategyBeanDoesntReachANewThread() {
        assertThat(mechanisms(FixtureScans.scan("threadhopsstrategybean"), "ingress:POST /thread"))
                .contains(OTHER_THREAD).doesNotContain(CHECK);
    }

    private static String requirement(ApplicationGraph graph, String ingress) {
        return Exposures.of(graph).stream().filter(exposure -> exposure.ingress().equals(ingress)).findFirst()
                .orElseThrow().requirement();
    }

    private static List<String> mechanisms(ApplicationGraph graph, String ingress) {
        return checks(graph, ingress).stream().map(AuthorizationLocation::mechanism).toList();
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
