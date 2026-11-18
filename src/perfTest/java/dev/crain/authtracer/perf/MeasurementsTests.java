package dev.crain.authtracer.perf;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.crain.authtracer.perf.Measurements.Baseline;
import dev.crain.authtracer.perf.Measurements.Measure;
import dev.crain.authtracer.perf.Measurements.Result;
import dev.crain.authtracer.perf.Measurements.Verdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * When a measure counts as a regression, and how a baseline is recorded.
 */
class MeasurementsTests {

    private static final String HERE = "this machine";

    @Test
    void aMeasureRegressesOnlyPastBothItsToleranceAndItsFloor() {
        Baseline baseline = baseline(HERE, Map.of("scan", Map.of("ms/op", 1000.0, "cpu ms/op", 0.2)));

        assertThat(verdict(baseline, Measure.WALL, 1150)).isEqualTo(Verdict.SAME);
        assertThat(verdict(baseline, Measure.WALL, 1250)).isEqualTo(Verdict.REGRESSED);
        // Half as much again, but by no more than the floor: noise in a small benchmark.
        assertThat(verdict(baseline, Measure.CPU, 0.3)).isEqualTo(Verdict.SAME);
        assertThat(verdict(baseline, Measure.CPU, 0.31)).isEqualTo(Verdict.REGRESSED);
    }

    @Test
    void aMeasureThatShrankPastItsToleranceImproved() {
        Baseline baseline = baseline(HERE, Map.of("scan", Map.of("ms/op", 1000.0)));

        assertThat(verdict(baseline, Measure.WALL, 700)).isEqualTo(Verdict.IMPROVED);
    }

    @Test
    void timesFromAnotherMachineAreShownButAllocationsAreCompared() {
        Baseline baseline = baseline("another machine", Map.of("scan", Map.of("ms/op", 100.0, "MB/op", 100.0)));

        assertThat(verdict(baseline, Measure.WALL, 500)).isEqualTo(Verdict.OTHER_MACHINE);
        assertThat(verdict(baseline, Measure.ALLOCATED, 110)).isEqualTo(Verdict.REGRESSED);
    }

    @Test
    void aMeasureTheBaselineDoesNotHaveIsNew() {
        assertThat(verdict(Baseline.NONE, Measure.WALL, 100)).isEqualTo(Verdict.NEW);
        assertThat(Measurements.compare(new Result("scan", Measure.WALL, 100), Baseline.NONE, HERE).change())
                .isEmpty();
    }

    @Test
    void recordingKeepsWhatTheBenchmarksThatDidNotRunHad(@TempDir Path dir) {
        Baseline before = baseline(HERE, Map.of("scan employee-service", Map.of("ms/op", 80.0),
                "diff", Map.of("ms/op", 60.0)));

        Baseline after = before.with(List.of(new Result("diff", Measure.WALL, 61.234)), HERE, "abc1234",
                "2026-10-18");
        after.write(dir.resolve("baseline.json"));

        Baseline read = Baseline.read(dir.resolve("baseline.json"));
        assertThat(read.metrics()).containsEntry("diff", Map.of("ms/op", 61.23))
                .containsEntry("scan employee-service", Map.of("ms/op", 80.0));
        assertThat(read.revision()).isEqualTo("abc1234");
    }

    @Test
    void numbersKeepThreeSignificantDigitsOrMore() {
        assertThat(Measurements.number(0.5312)).isEqualTo("0.531");
        assertThat(Measurements.number(61.234)).isEqualTo("61.23");
        assertThat(Measurements.number(2033.94)).isEqualTo("2,033.9");
    }

    private static Verdict verdict(Baseline baseline, Measure measure, double now) {
        return Measurements.compare(new Result("scan", measure, now), baseline, HERE).verdict();
    }

    private static Baseline baseline(String machine, Map<String, Map<String, Double>> metrics) {
        return new Baseline(machine, "abc", "2026-10-18", new LinkedHashMap<>(metrics));
    }
}
