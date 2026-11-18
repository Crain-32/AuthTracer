package dev.crain.authtracer.perf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import dev.crain.authtracer.perf.Measurements.Baseline;
import dev.crain.authtracer.perf.Measurements.Compared;
import dev.crain.authtracer.perf.Measurements.Result;
import dev.crain.authtracer.perf.Measurements.Verdict;
import dev.crain.authtracer.scan.ProjectScans;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * How long AuthTracer takes, and how much it allocates, to scan, link, compute exposures, diff and write JSON on fixed
 * inputs ({@link Benchmarks}, which JMH runs, each in a JVM of its own), and how big the UI it serves is, against the
 * baseline in {@code src/perfTest/resources/baseline.json}.
 * <p>
 * A benchmark fails when a measure grew past its tolerance ({@link Measurements.Measure}); times are compared only on
 * the machine the baseline was recorded on, allocations and sizes anywhere. The report, with every measure against the
 * baseline, is {@code build/reports/perf/perf.md}. After a change meant to cost more, or one that made something
 * faster, {@code ./gradlew perfTest -PupdatePerf=true} records a new baseline: commit it with the change, so the
 * baseline's history is the performance's.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PerformanceTests {

    private static final Path SERVICES = Path.of(System.getProperty("authtracer.services.dir"));
    private static final Path BASELINE = Path.of(System.getProperty("authtracer.perf.baseline"));
    private static final Path REPORT = Path.of(System.getProperty("authtracer.perf.report"));
    private static final Path UI = Path.of(System.getProperty("authtracer.perf.ui"));
    private static final boolean UPDATE = Boolean.getBoolean("authtracer.perf.update");

    private static final List<Result> RESULTS = new ArrayList<>();
    private static final String MACHINE = Measurements.machine();
    private static Baseline baseline;

    @BeforeAll
    static void readBaseline() {
        baseline = Baseline.read(BASELINE);
    }

    @Test
    @Order(1)
    void scanningFixtures() {
        record(jmh("scanFixtures", "scan " + Benchmarks.FIXTURES.size() + " fixtures"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"profile-service", "employee-service", "identity-service", "payroll-service"})
    @Order(2)
    void scanningAnExampleService(String service) {
        assumeTrue(Files.isDirectory(SERVICES.resolve(service)), service + " isn't checked out in " + SERVICES);

        record(jmh("scanService", "scan " + service, "service", service));
    }

    @Test
    @Order(3)
    void linkingTheExampleServicesWithTheirTraces() {
        record(jmh("link", "link example services with traces"));
    }

    @Test
    @Order(4)
    void exposuresOfTheExampleSystem() {
        record(jmh("exposures", "exposures of example system"));
    }

    @Test
    @Order(5)
    void diffingTheExampleSystem() {
        record(jmh("diff", "diff example system"));
    }

    @Test
    @Order(6)
    void writingAndReadingTheExampleSystemsJson() {
        record(jmh("jsonRoundTrip", "JSON round trip of example system"));
    }

    @Test
    @Order(7)
    void theUiScriptsAndStyles() throws IOException {
        List<Path> files;
        try (Stream<Path> all = Files.walk(UI)) {
            files = all.filter(file -> file.toString().endsWith(".js") || file.toString().endsWith(".css")).sorted()
                    .toList();
        }
        assertThat(files).as("the UI is built into " + UI).isNotEmpty();

        record(Measurements.size("UI scripts and styles", files));
    }

    @AfterAll
    static void report() throws IOException {
        String revision = ProjectScans.gitRevision(Path.of("."));
        List<Compared> compared = RESULTS.stream().map(result -> Measurements.compare(result, baseline, MACHINE))
                .toList();
        String report = Measurements.report(compared, baseline, MACHINE, revision);
        Files.createDirectories(REPORT);
        Files.writeString(REPORT.resolve("perf.md"), report);
        System.out.println(report);
        if (UPDATE) {
            baseline.with(RESULTS, MACHINE, revision, LocalDate.now().toString()).write(BASELINE);
            System.out.println("Recorded the baseline in " + BASELINE);
        }
    }

    /**
     * Keeps the benchmark's results for the report, and fails it when one regressed (unless a baseline is being
     * recorded).
     */
    private static void record(List<Result> results) {
        RESULTS.addAll(results);
        if (!UPDATE) {
            assertThat(results.stream().map(result -> Measurements.compare(result, baseline, MACHINE))
                    .filter(compared -> compared.verdict() == Verdict.REGRESSED)
                    .map(compared -> compared.result().measure().label + " " + Measurements.number(compared
                            .result().value()) + " against " + Measurements.number(compared.baseline()) + " ("
                            + compared.change() + ")"))
                    .as("Regressed against the baseline; if it's meant to, record a new one with -PupdatePerf=true")
                    .isEmpty();
        }
    }

    /**
     * Runs the benchmark method of {@link Benchmarks} with JMH: forked with this JVM's flags and system properties (the
     * perfTest task's), with JMH's GC profiler for allocations and {@link CpuTime}.
     *
     * @param params the benchmark's {@code @Param} values, name then value
     */
    private static List<Result> jmh(String method, String benchmark, String... params) {
        ChainedOptionsBuilder options = new OptionsBuilder()
                .include(Pattern.quote(Benchmarks.class.getName() + "." + method) + "$")
                .addProfiler(GCProfiler.class).addProfiler(CpuTime.class).shouldFailOnError(true);
        for (int i = 0; i < params.length; i += 2) {
            options.param(params[i], params[i + 1]);
        }
        try {
            return Measurements.of(benchmark, new Runner(options.build()).runSingle());
        } catch (RunnerException e) {
            throw new IllegalStateException(benchmark + " failed under JMH", e);
        }
    }
}
