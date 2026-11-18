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
 * Decision 0062: lambdas and method references handed to another thread leave the caller's SecurityContext behind.
 */
class ThreadHopFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("threadhops");

    @Test
    void workHandedToAnotherThreadIsCheckedThereWithoutTheCaller() {
        for (String ingress : List.of("ingress:GET /submit", "ingress:POST /refresh", "ingress:POST /thread")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains("@PreAuthorize (other thread)")
                    .doesNotContain("@PreAuthorize");
            assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals(ingress)).first()
                    .satisfies(exposure -> assertThat(exposure.requirement()).doesNotContain("denyAll", "ROLE_ADMIN"));
        }
        assertThat(checks(graph, "ingress:GET /submit")).filteredOn(check -> check.mechanism().endsWith("thread)"))
                .singleElement()
                .satisfies(check -> assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.DENY_ALL));
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("On GET /submit", "Reports#build", "the thread ExecutorService.submit hands it to"));
    }

    @Test
    void aCallerThatJoinsTheOtherThreadFailsWithIt() {
        // Decision 0084: join() rethrows the other thread's AuthenticationCredentialsNotFoundException.
        for (String ingress : List.of("ingress:GET /supply", "ingress:GET /then")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains("@PreAuthorize (other thread, waited for)")
                    .doesNotContain("@PreAuthorize", "@PreAuthorize (other thread)");
            assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.ingress().equals(ingress)).first()
                    .satisfies(exposure -> assertThat(exposure.requirement()).contains("denyAll"));
        }
    }

    @Test
    void workOnTheCallersThreadKeepsTheCheck() {
        for (String ingress : List.of("ingress:GET /sync", "ingress:GET /stream")) {
            assertThat(mechanisms(graph, ingress)).as(ingress).contains("@PreAuthorize")
                    .doesNotContain("@PreAuthorize (other thread)");
        }
    }

    @Test
    void theInheritableStrategyReachesANewThread() {
        ApplicationGraph inherited = FixtureScans.scan("threadhopsinherited");
        assertThat(mechanisms(inherited, "ingress:POST /thread")).contains("@PreAuthorize")
                .doesNotContain("@PreAuthorize (other thread)");
    }

    @Test
    void aPoolsThreadKeepsTheContextOfTheRequestThatCreatedIt() {
        // Decision 0084, amended: the inheritable strategy carries a context to a pool's thread, but not this caller's.
        ApplicationGraph pooled = FixtureScans.scan("threadhopspooled");
        for (String ingress : List.of("ingress:POST /submit", "ingress:GET /supply", "ingress:POST /simple",
                "ingress:POST /thread", "ingress:POST /unnamed", "ingress:POST /pooled", "ingress:POST /per-task")) {
            assertThat(mechanisms(pooled, ingress)).as(ingress).contains("@PreAuthorize")
                    .doesNotContain("@PreAuthorize (other thread)");
        }
        // A thread started for each task, by the caller, gets the caller's.
        assertThat(pooled.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.AUTHORITIES_IN_CODE)
                .extracting(Finding::message).hasSize(4)
                .anySatisfy(message -> assertThat(message).contains("On POST /submit: @PreAuthorize on",
                        "Reports#build", "runs on a pooled thread (ExecutorService.submit)",
                        "the check decides for whichever request that was"))
                .anySatisfy(message -> assertThat(message).contains("On GET /supply",
                        "(CompletableFuture.supplyAsync)"))
                .anySatisfy(message -> assertThat(message).contains("On POST /unnamed", "Exports#unnamed",
                        "(@Async's executor)"))
                .anySatisfy(message -> assertThat(message).contains("On POST /pooled",
                        "(@Async(\"reportsExecutor\")'s executor)"));
    }

    @Test
    void aTaskDecoratorReachesTheExecutorButNotTheCommonPool() {
        ApplicationGraph decorated = FixtureScans.scan("threadhopsdecorated");
        assertThat(mechanisms(decorated, "ingress:GET /decorated")).contains("@PreAuthorize")
                .doesNotContain("@PreAuthorize (other thread)");
        assertThat(mechanisms(decorated, "ingress:GET /common")).contains("@PreAuthorize (other thread, waited for)")
                .doesNotContain("@PreAuthorize");
    }

    @Test
    void executorsVirtualThreadsAndThreadBuildersAreOtherThreadsToo() {
        ApplicationGraph forms = FixtureScans.scan("threadhopsforms");
        for (String ingress : List.of("ingress:POST /virtual", "ingress:POST /built", "ingress:POST /unstarted",
                "ingress:POST /executor", "ingress:POST /stored")) {
            assertThat(mechanisms(forms, ingress)).as(ingress).contains("@PreAuthorize (other thread)")
                    .doesNotContain("@PreAuthorize");
        }
        assertThat(mechanisms(forms, "ingress:GET /pooled")).contains("@PreAuthorize (other thread, waited for)")
                .doesNotContain("@PreAuthorize");
        assertThat(mechanisms(forms, "ingress:GET /applied")).contains("@PreAuthorize")
                .doesNotContain("@PreAuthorize (other thread)");
    }

    @Test
    void springSecuritysDelegatingExecutorCarriesTheContext() {
        ApplicationGraph delegating = FixtureScans.scan("threadhopsdelegating");
        for (String ingress : List.of("ingress:GET /submitted", "ingress:GET /pooled")) {
            assertThat(mechanisms(delegating, ingress)).as(ingress).contains("@PreAuthorize")
                    .doesNotContain("@PreAuthorize (other thread)");
        }
    }

    @Test
    void aTaskDecoratorComponentCarriesTheContext() {
        assertThat(mechanisms(FixtureScans.scan("threadhopsdecorators"), "ingress:POST /refresh"))
                .contains("@PreAuthorize").doesNotContain("@PreAuthorize (other thread)");
    }

    @Test
    void aStrategyFromAPropertyMayBeTheInheritableOne() {
        ApplicationGraph strategy = FixtureScans.scan("threadhopsstrategy");
        for (String ingress : List.of("ingress:POST /thread", "ingress:GET /supply")) {
            assertThat(mechanisms(strategy, ingress)).as(ingress).contains("@PreAuthorize")
                    .doesNotContain("@PreAuthorize (other thread)");
        }
    }

    private static List<String> mechanisms(ApplicationGraph graph, String ingress) {
        return checks(graph, ingress).stream().map(AuthorizationLocation::mechanism).toList();
    }

    private static List<AuthorizationLocation> checks(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
