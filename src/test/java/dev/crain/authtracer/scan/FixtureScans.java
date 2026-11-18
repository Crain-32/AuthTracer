package dev.crain.authtracer.scan;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.provided.ProvidedFacts;

/**
 * Scans the compiled fixture applications ({@code src/fixtures/java}), one package per application.
 */
public final class FixtureScans {

    private static final Map<String, ApplicationGraph> CACHE = new ConcurrentHashMap<>();

    private FixtureScans() {
    }

    /**
     * With the fixture's own {@code authtracer.yaml}, when its resources have one.
     */
    public static ApplicationGraph scan(String fixturePackage) {
        return CACHE.computeIfAbsent(fixturePackage, pkg -> {
            Path facts = Path.of("src/fixtures/resources", pkg, ProvidedFacts.LOCAL_FILE);
            return scan(pkg, Files.isRegularFile(facts) ? ProvidedFacts.load(Optional.of(facts), Optional.empty(), pkg)
                    : ProvidedFacts.NONE);
        });
    }

    /**
     * Uncached, with Provided facts.
     */
    public static ApplicationGraph scan(String fixturePackage, ProvidedFacts facts) {
        // A fixture's application.properties, if it has one, lives in src/fixtures/resources/<package>.
        Path resources = Path.of("src/fixtures/resources", fixturePackage);
        return ProjectScans.defaultScanner().scan(new ScanInput(fixturePackage, "test",
                paths("authtracer.fixtures.classes"), paths("authtracer.fixtures.libraries"),
                Files.isDirectory(resources) ? List.of(resources) : List.of(),
                List.of("fixtures." + fixturePackage + "."), facts));
    }

    /**
     * Uncached, as an application that doesn't depend on the libraries named, e.g.
     * {@code scanWithout("cloudclient", "spring-cloud-config-client")}: the fixtures share one classpath, and this
     * leaves out the jars whose names start with one of them.
     */
    public static ApplicationGraph scanWithout(String fixturePackage, String... libraries) {
        Path resources = Path.of("src/fixtures/resources", fixturePackage);
        List<Path> kept = paths("authtracer.fixtures.libraries").stream()
                .filter(jar -> Arrays.stream(libraries).noneMatch(library -> jar.getFileName().toString()
                        .startsWith(library + "-")))
                .toList();
        return ProjectScans.defaultScanner().scan(new ScanInput(fixturePackage, "test",
                paths("authtracer.fixtures.classes"), kept,
                Files.isDirectory(resources) ? List.of(resources) : List.of(),
                List.of("fixtures." + fixturePackage + "."), ProvidedFacts.NONE));
    }

    /**
     * Uncached, with library jars besides the fixtures' own, e.g. one whose {@code META-INF/spring.factories} names
     * something Spring applies.
     */
    public static ApplicationGraph scanWithLibraries(String fixturePackage, List<Path> extra) {
        Path resources = Path.of("src/fixtures/resources", fixturePackage);
        List<Path> libraries = new ArrayList<>(paths("authtracer.fixtures.libraries"));
        libraries.addAll(extra);
        return ProjectScans.defaultScanner().scan(new ScanInput(fixturePackage, "test",
                paths("authtracer.fixtures.classes"), libraries,
                Files.isDirectory(resources) ? List.of(resources) : List.of(),
                List.of("fixtures." + fixturePackage + "."), ProvidedFacts.NONE));
    }

    /**
     * Uncached, as an application without the libraries of the Maven groups named, e.g.
     * {@code scanWithoutGroups("jacksonnames", "tools.jackson.core")} for one on Jackson 2 only, whose jars' names
     * are Jackson 3's too.
     */
    public static ApplicationGraph scanWithoutGroups(String fixturePackage, String... groups) {
        Path resources = Path.of("src/fixtures/resources", fixturePackage);
        List<Path> kept = paths("authtracer.fixtures.libraries").stream()
                .filter(jar -> Arrays.stream(groups).noneMatch(group -> jar.toString().contains(
                        File.separator + group + File.separator)))
                .toList();
        return ProjectScans.defaultScanner().scan(new ScanInput(fixturePackage, "test",
                paths("authtracer.fixtures.classes"), kept,
                Files.isDirectory(resources) ? List.of(resources) : List.of(),
                List.of("fixtures." + fixturePackage + "."), ProvidedFacts.NONE));
    }

    /**
     * Uncached, with the fixture's classes woven with Spring Security's aspects, as ajc (or a load-time weaver) weaves
     * an application's classes for {@code @EnableMethodSecurity(mode = AdviceMode.ASPECTJ)}.
     */
    public static ApplicationGraph scanWoven(String fixturePackage) {
        try {
            return scanWoven(fixturePackage, Weaving.weave(fixturePackage,
                    Files.createTempDirectory("woven-" + fixturePackage)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Uncached, from the fixture's classes as {@link Weaving#weave} wove them into {@code classes}.
     */
    public static ApplicationGraph scanWoven(String fixturePackage, Path classes) {
        Path resources = Path.of("src/fixtures/resources", fixturePackage);
        return ProjectScans.defaultScanner().scan(new ScanInput(fixturePackage, "test",
                List.of(classes), paths("authtracer.fixtures.libraries"),
                Files.isDirectory(resources) ? List.of(resources) : List.of(),
                List.of("fixtures." + fixturePackage + "."), ProvidedFacts.NONE));
    }

    /**
     * The request-level rule an Ingress's path starts with, e.g. {@code rule(graph, "GET /orders/{id}")}.
     */
    public static AuthorizationLocation rule(ApplicationGraph graph, String ingress) {
        List<String> path = path(graph, "ingress:" + ingress);
        if (path.isEmpty()) {
            throw new AssertionError("No path for " + ingress);
        }
        return (AuthorizationLocation) graph.node(path.getFirst()).orElseThrow();
    }

    /**
     * The node ids along one Ingress's path, in order.
     */
    public static List<String> path(ApplicationGraph graph, String ingressId) {
        return graph.path(ingressId).stream().map(Edge::to).toList();
    }

    static List<Path> paths(String property) {
        String value = System.getProperty(property);
        if (value == null) {
            throw new IllegalStateException(property + " is not set; run the tests through Gradle");
        }
        return Arrays.stream(value.split(File.pathSeparator)).filter(entry -> !entry.isBlank()).map(Path::of)
                .toList();
    }
}
