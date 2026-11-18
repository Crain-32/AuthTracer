package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Stream;

import dev.crain.authtracer.graph.GraphJson;
import dev.crain.authtracer.provided.ProvidedFacts;
import org.junit.jupiter.api.Test;

/**
 * Scanning the same classes twice gives the same graph: what a diff reports must be a change in the application,
 * never in the order a scan happened to visit it. An integration test since it scans every fixture twice, a few at a
 * time.
 */
class RepeatableScansTests {

    private static final int THREADS = 4;

    @Test
    void everyFixtureScansToTheSameGraphTwice() throws Exception {
        List<String> fixtures = fixtures();
        ForkJoinPool pool = new ForkJoinPool(THREADS);
        try {
            List<String> differing = pool.submit(() -> fixtures.parallelStream().map(RepeatableScansTests::differs)
                    .filter(Objects::nonNull).sorted().toList()).get();
            assertThat(differing).isEmpty();
        }
        catch (ExecutionException ex) {
            throw ex.getCause() instanceof Exception cause ? cause : ex;
        }
        finally {
            pool.shutdown();
        }
    }

    /**
     * How the fixture's two scans differ, {@code null} when they don't.
     */
    private static String differs(String fixture) {
        String first = GraphJson.write(FixtureScans.scan(fixture, ProvidedFacts.NONE));
        String second = GraphJson.write(FixtureScans.scan(fixture, ProvidedFacts.NONE));
        return first.equals(second) ? null : fixture + ": " + firstDifference(first, second);
    }

    private static List<String> fixtures() throws IOException {
        List<String> fixtures = new ArrayList<>();
        for (String language : List.of("java", "kotlin", "groovy")) {
            try (Stream<Path> packages = Files.list(Path.of("src/fixtures", language, "fixtures"))) {
                packages.filter(Files::isDirectory).map(pkg -> pkg.getFileName().toString()).sorted()
                        .forEach(fixtures::add);
            }
        }
        return fixtures;
    }

    private static String firstDifference(String first, String second) {
        List<String> a = first.lines().toList();
        List<String> b = second.lines().toList();
        for (int i = 0; i < Math.min(a.size(), b.size()); i++) {
            if (!a.get(i).equals(b.get(i))) {
                return "line " + (i + 1) + ": " + a.get(i).strip() + " | " + b.get(i).strip();
            }
        }
        return "lengths " + a.size() + " and " + b.size();
    }
}
