package dev.crain.authtracer.perf;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.GraphDiff;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.ApplicationScanner;
import dev.crain.authtracer.scan.ProjectScans;
import dev.crain.authtracer.scan.ScanInput;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * The benchmarks, as JMH runs them: {@link PerformanceTests} runs each in a JVM of its own (with the perfTest task's
 * flags and system properties), warms it up and measures the average time of one operation. Fixed inputs: fixtures of
 * most kinds the scanner reads, the example services (built once, outside the measurement), and their golden graphs
 * linked with recorded traces.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class Benchmarks {

    /**
     * Fixtures of most kinds the scanner reads: Spring MVC and WebFlux, GraphQL, gRPC, messaging, views, STOMP,
     * RSocket, JAX-RS, the Kotlin and Groovy DSLs, XML configuration, thread hand-offs, an authorization server.
     */
    static final List<String> FIXTURES = List.of("web", "webflux", "graphql", "grpc", "messaging", "views",
            "stomp", "rsocket", "jaxrs", "kotlindsl", "groovydsl", "xmlconfig", "threadhops", "authserver");
    static final List<String> SERVICES = List.of("profile-service", "employee-service", "identity-service",
            "payroll-service");

    private static final ApplicationScanner SCANNER = ProjectScans.defaultScanner();

    @State(Scope.Benchmark)
    public static class Fixtures {

        List<ScanInput> inputs;

        @Setup
        public void read() {
            inputs = FIXTURES.stream().map(Fixtures::fixture).toList();
        }

        private static ScanInput fixture(String fixturePackage) {
            Path resources = Path.of("src/fixtures/resources", fixturePackage);
            return new ScanInput(fixturePackage, "perf", paths("authtracer.fixtures.classes"),
                    paths("authtracer.fixtures.libraries"), Files.isDirectory(resources) ? List.of(resources)
                            : List.of(), List.of("fixtures." + fixturePackage + "."), ProvidedFacts.NONE);
        }

        private static List<Path> paths(String property) {
            return Stream.of(System.getProperty(property).split(File.pathSeparator)).filter(path -> !path.isEmpty())
                    .map(Path::of).toList();
        }
    }

    @State(Scope.Benchmark)
    public static class Service {

        @Param({"profile-service", "employee-service", "identity-service", "payroll-service"})
        public String service;

        ScanInput input;

        @Setup
        public void build() {
            input = ProjectScans.project(Path.of(System.getProperty("authtracer.services.dir")).resolve(service),
                    null, "perf", List.of());
        }
    }

    /**
     * The example services' golden graphs, linked with their recorded traces.
     */
    @State(Scope.Benchmark)
    public static class ExampleSystem {

        List<ApplicationGraph> graphs;
        Path traces;
        SystemGraph system;

        @Setup
        public void link() {
            Path golden = Path.of(System.getProperty("authtracer.golden.dir"));
            graphs = SERVICES.stream().map(name -> GraphJson.read(golden.resolve(name + ".json"))).toList();
            traces = Path.of(System.getProperty("authtracer.perf.traces"));
            system = new Linker().link(graphs, ZipkinTraces.file(traces));
        }
    }

    @Benchmark
    public List<ApplicationGraph> scanFixtures(Fixtures fixtures) {
        return fixtures.inputs.stream().map(SCANNER::scan).toList();
    }

    @Benchmark
    public ApplicationGraph scanService(Service service) {
        return SCANNER.scan(service.input);
    }

    @Benchmark
    public SystemGraph link(ExampleSystem example) {
        return new Linker().link(example.graphs, ZipkinTraces.file(example.traces));
    }

    @Benchmark
    public Object exposures(ExampleSystem example) {
        return Exposures.of(example.system);
    }

    @Benchmark
    public Object diff(ExampleSystem example) {
        return GraphDiff.compare(example.system, example.system);
    }

    @Benchmark
    public SystemGraph jsonRoundTrip(ExampleSystem example) {
        return GraphJson.readSystem(GraphJson.write(example.system));
    }
}
