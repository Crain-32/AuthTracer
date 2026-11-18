package dev.crain.authtracer.perf;

import java.lang.management.ManagementFactory;
import java.util.Collection;
import java.util.List;

import com.sun.management.OperatingSystemMXBean;
import org.openjdk.jmh.infra.BenchmarkParams;
import org.openjdk.jmh.infra.IterationParams;
import org.openjdk.jmh.profile.InternalProfiler;
import org.openjdk.jmh.results.AggregationPolicy;
import org.openjdk.jmh.results.IterationResult;
import org.openjdk.jmh.results.Result;
import org.openjdk.jmh.results.ScalarResult;

/**
 * A JMH profiler: the process's CPU time per operation over each iteration, the JIT's and the garbage collector's
 * threads included, which JMH's own profilers don't measure.
 */
public final class CpuTime implements InternalProfiler {

    static final String LABEL = "cpu.time.norm";

    private static final OperatingSystemMXBean OS = (OperatingSystemMXBean) ManagementFactory
            .getOperatingSystemMXBean();

    private long before;

    @Override
    public String getDescription() {
        return "The process's CPU time per operation";
    }

    @Override
    public void beforeIteration(BenchmarkParams benchmarkParams, IterationParams iterationParams) {
        before = OS.getProcessCpuTime();
    }

    @Override
    public Collection<? extends Result> afterIteration(BenchmarkParams benchmarkParams,
            IterationParams iterationParams, IterationResult result) {
        long ops = result.getMetadata().getAllOps();
        double millis = (OS.getProcessCpuTime() - before) / 1e6;
        return List.of(new ScalarResult(LABEL, ops == 0 ? Double.NaN : millis / ops, "ms/op",
                AggregationPolicy.AVG));
    }
}
