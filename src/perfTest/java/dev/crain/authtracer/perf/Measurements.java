package dev.crain.authtracer.perf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.math.BigDecimal;
import java.math.MathContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import com.sun.management.OperatingSystemMXBean;
import org.openjdk.jmh.results.RunResult;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * What JMH measured of the benchmarks, and the UI's size, compared with the recorded baseline.
 */
final class Measurements {

    /**
     * JMH's GC profiler's allocation per operation, in bytes.
     */
    static final String ALLOCATION = "gc.alloc.rate.norm";

    private static final OperatingSystemMXBean OS = (OperatingSystemMXBean) ManagementFactory
            .getOperatingSystemMXBean();
    private static final JsonMapper JSON = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();

    private Measurements() {
    }

    /**
     * What is measured, and how much it may grow before it counts as a regression: by more than the tolerance and more
     * than the floor, which keeps a small benchmark's noise from failing it. Two full runs on a quiet machine, when
     * the benchmarks moved to JMH, differed by up to 3% in time and CPU time and 1.4% in allocation.
     *
     * @param machineBound whether it depends on the machine, so is compared only on the baseline's
     */
    enum Measure {
        /** The average time of one operation, as JMH measures it. */
        WALL("ms/op", 0.20, 0.05, true),
        /** The process's CPU time per operation ({@link CpuTime}), the JIT's and the garbage collector's included. */
        CPU("cpu ms/op", 0.20, 0.1, true),
        /** What one operation allocated (JMH's GC profiler). */
        ALLOCATED("MB/op", 0.05, 0.05, false),
        /** Bytes on disk. */
        SIZE("size KB", 0.05, 2, false),
        /** Bytes as a browser downloads them, gzipped. */
        GZIP("gzip KB", 0.05, 1, false);

        final String label;
        final double tolerance;
        final double floor;
        final boolean machineBound;

        Measure(String label, double tolerance, double floor, boolean machineBound) {
            this.label = label;
            this.tolerance = tolerance;
            this.floor = floor;
            this.machineBound = machineBound;
        }
    }

    record Result(String benchmark, Measure measure, double value) {
    }

    enum Verdict {
        SAME, REGRESSED, IMPROVED, NEW,
        /** A time, measured on another machine than the baseline's: shown, not compared. */
        OTHER_MACHINE
    }

    record Compared(Result result, Double baseline, Verdict verdict) {

        String change() {
            return baseline == null || baseline == 0 ? "" : String.format(Locale.ROOT, "%+.1f%%",
                    (result.value() - baseline) / baseline * 100);
        }
    }

    /**
     * The baseline: what each benchmark measured when it was recorded, on what machine, at what revision.
     *
     * @param metrics each benchmark's measures, by their labels
     */
    record Baseline(String machine, String revision, String recorded, Map<String, Map<String, Double>> metrics) {

        static final Baseline NONE = new Baseline(null, null, null, Map.of());

        static Baseline read(Path file) {
            try {
                return Files.exists(file) ? JSON.readValue(Files.readString(file), Baseline.class) : NONE;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        Double value(Result result) {
            return metrics.getOrDefault(result.benchmark(), Map.of()).get(result.measure().label);
        }

        /**
         * This baseline with the results (to four significant digits) in place of what it had for their benchmarks;
         * those that didn't run (an example service that isn't checked out) keep what they had.
         */
        Baseline with(List<Result> results, String machine, String revision, String recorded) {
            Map<String, Map<String, Double>> merged = new LinkedHashMap<>();
            for (Result result : results) {
                merged.computeIfAbsent(result.benchmark(), name -> new LinkedHashMap<>())
                        .put(result.measure().label, new BigDecimal(result.value())
                                .round(new MathContext(4)).doubleValue());
            }
            metrics.forEach(merged::putIfAbsent);
            return new Baseline(machine, revision, recorded, merged);
        }

        void write(Path file) {
            try {
                Files.writeString(file, JSON.writeValueAsString(this) + "\n");
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    /**
     * What JMH measured of the benchmark: its average time, and the CPU time and allocation per operation.
     */
    static List<Result> of(String benchmark, RunResult run) {
        Map<String, org.openjdk.jmh.results.Result> secondary = run.getSecondaryResults();
        return List.of(new Result(benchmark, Measure.WALL, run.getPrimaryResult().getScore()),
                new Result(benchmark, Measure.CPU, secondary.get(CpuTime.LABEL).getScore()),
                new Result(benchmark, Measure.ALLOCATED, secondary.get(ALLOCATION).getScore() / (1024 * 1024)));
    }

    /**
     * The files' size on disk and gzipped, in KB.
     */
    static List<Result> size(String benchmark, List<Path> files) {
        long raw = 0;
        ByteArrayOutputStream gzipped = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(gzipped)) {
            for (Path file : files) {
                byte[] bytes = Files.readAllBytes(file);
                raw += bytes.length;
                gzip.write(bytes);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return List.of(new Result(benchmark, Measure.SIZE, raw / 1024.0),
                new Result(benchmark, Measure.GZIP, gzipped.size() / 1024.0));
    }

    static Compared compare(Result result, Baseline baseline, String machine) {
        Double before = baseline.value(result);
        if (before == null) {
            return new Compared(result, null, Verdict.NEW);
        }
        Measure measure = result.measure();
        if (measure.machineBound && !machine.equals(baseline.machine())) {
            return new Compared(result, before, Verdict.OTHER_MACHINE);
        }
        double change = result.value() - before;
        if (change > before * measure.tolerance && change > measure.floor) {
            return new Compared(result, before, Verdict.REGRESSED);
        }
        if (-change > before * measure.tolerance && -change > measure.floor) {
            return new Compared(result, before, Verdict.IMPROVED);
        }
        return new Compared(result, before, Verdict.SAME);
    }

    /**
     * The machine, as far as a JVM can tell one from another: times are compared only on the baseline's.
     */
    static String machine() {
        return System.getProperty("os.name") + " " + System.getProperty("os.arch") + ", "
                + Runtime.getRuntime().availableProcessors() + " cores, "
                + Math.round(OS.getTotalMemorySize() / (1024.0 * 1024 * 1024)) + " GB, Java "
                + Runtime.version().feature();
    }

    /**
     * The report: each measure against the baseline, regressions marked.
     */
    static String report(List<Compared> compared, Baseline baseline, String machine, String revision) {
        StringBuilder report = new StringBuilder("# Performance\n\n");
        report.append("Measured on ").append(machine).append(" at ").append(revision).append(". ");
        report.append(baseline.machine() == null ? "There is no baseline yet."
                : "Baseline: " + baseline.recorded() + " at " + baseline.revision() + ", on " + baseline.machine()
                        + (baseline.machine().equals(machine) ? "." : ": times aren't compared on another machine."));
        report.append("\n\n| Benchmark | Measure | Baseline | Now | Change | |\n|---|---|---:|---:|---:|---|\n");
        for (Compared each : compared) {
            Result result = each.result();
            report.append("| ").append(result.benchmark()).append(" | ").append(result.measure().label).append(" | ")
                    .append(each.baseline() == null ? "" : number(each.baseline())).append(" | ")
                    .append(number(result.value())).append(" | ").append(each.change()).append(" | ")
                    .append(switch (each.verdict()) {
                        case REGRESSED -> "**regressed**";
                        case IMPROVED -> "improved";
                        case NEW -> "new";
                        case OTHER_MACHINE -> "other machine";
                        case SAME -> "";
                    }).append(" |\n");
        }
        return report.toString();
    }

    static String number(double value) {
        return String.format(Locale.ROOT, value < 1 ? "%.3f" : value < 100 ? "%.2f" : "%,.1f", value);
    }
}
