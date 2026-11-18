package dev.crain.authtracer.mutation;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import dev.crain.authtracer.diff.DiffReport;
import dev.crain.authtracer.diff.GraphDiff;
import dev.crain.authtracer.conformance.ConformanceExpectations;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.ProvidedFact;
import dev.crain.authtracer.provided.ProvidedFacts;
import dev.crain.authtracer.scan.FixtureScans;
import dev.crain.authtracer.scan.ProjectScans;
import dev.crain.authtracer.scan.ScanInput;

/**
 * The first half of {@code ./gradlew mutationTest}: for each Java fixture, every mutation {@link Mutators} finds,
 * compiled, scanned and diffed against the fixture as it is (compiled the same way). The second half
 * ({@code MutationTests}, on the fixtures' classpath) boots each mutant and asks Spring whether it got weaker.
 *
 * <p>Writes to the directory given:
 * <ul>
 * <li>{@code classes/<fixture>/base} and {@code classes/<fixture>/<n>}: the package compiled, as it is and mutated;
 * <li>{@code mutants.tsv}: {@code id, fixture, operator, file:line, description, status, detail} (status
 * {@code BASE}, {@code SCANNED}, {@code NOT_COMPILED}, {@code SCAN_FAILED});
 * <li>{@code changes.tsv}: {@code id, kind, severity, endpoint, field, before, after}, the diff of each mutant
 * against its base (endpoint with route variables unnamed, as the diff tells endpoints apart);
 * <li>{@code expected.tsv}: {@code id, method, route, params, clauses, requirement, endpoint}, what each graph
 * (the base's, each mutant's) says each endpoint needs, as conformanceExpectations writes it, and after each the
 * response fields that ask more, with {@code field, answers, body} after those cells.
 * </ul>
 */
public final class MutationScans {

    private MutationScans() {
    }

    /**
     * @param args the directory to write; {@code all} or a comma-separated list of fixture packages; {@code all}
     *        or a comma-separated list of operators; the most mutants of one operator per fixture ({@code 0}: all)
     */
    public static void main(String[] args) throws IOException {
        Path out = Path.of(args[0]);
        List<String> fixtures = args[1].equals("all") ? all() : List.of(args[1].split(","));
        Set<Mutation.Operator> operators = args[2].equals("all") ? Set.of(Mutation.Operator.values())
                : Arrays.stream(args[2].split(",")).map(Mutation.Operator::valueOf).collect(Collectors.toSet());
        int cap = Integer.parseInt(args[3]);
        new MutationScans.Run(out, operators, cap).run(fixtures);
    }

    /**
     * A fixture as it is and mutated, both compiled and scanned the way mutationTest does.
     *
     * @param mutation the mutation's description
     */
    public record Mutated(ApplicationGraph base, ApplicationGraph mutant, String mutation) {

        public DiffReport diff() {
            return GraphDiff.compare(base, mutant);
        }
    }

    /**
     * The fixture as it is and with the first mutation whose description contains {@code change}, e.g.
     * {@code mutate("dslhelpers", "adminRules(): .anyRequest().hasRole(\"ADMIN\") to permitAll()")}.
     */
    public static Mutated mutate(String fixture, String change) {
        try {
            Path out = Files.createTempDirectory("authtracer-mutant");
            return new Run(out, Set.of(Mutation.Operator.values()), 0).mutated(fixture, change);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static List<String> all() throws IOException {
        try (Stream<Path> children = Files.list(Path.of("src/fixtures/java/fixtures"))) {
            return children.filter(Files::isDirectory).map(child -> child.getFileName().toString()).sorted().toList();
        }
    }

    /**
     * The mutants of one operator, at most {@code cap} of them, spread over the fixture.
     */
    static List<Mutation> capped(List<Mutation> mutations, Set<Mutation.Operator> operators, int cap) {
        Map<Mutation.Operator, List<Mutation>> byOperator = new EnumMap<>(Mutation.Operator.class);
        mutations.stream().filter(mutation -> operators.contains(mutation.operator()))
                .forEach(mutation -> byOperator.computeIfAbsent(mutation.operator(), key -> new ArrayList<>())
                        .add(mutation));
        List<Mutation> kept = new ArrayList<>();
        byOperator.values().forEach(list -> {
            if (cap <= 0 || list.size() <= cap) {
                kept.addAll(list);
            } else {
                for (int i = 0; i < cap; i++) {
                    kept.add(list.get(i * list.size() / cap));
                }
            }
        });
        return kept;
    }

    /**
     * What a graph says each endpoint needs, one line each, and after it each response field that asks more (see
     * ConformanceExpectations).
     */
    static List<String> expectations(String id, ApplicationGraph graph) {
        List<String> lines = new ArrayList<>();
        for (ConformanceExpectations.Line line : ConformanceExpectations.of(graph)) {
            List<String> cells = new ArrayList<>(List.of(id));
            cells.addAll(line.cells(List.of(key(line.ingress().endpoint()))));
            lines.add(String.join("\t", cells));
        }
        return lines;
    }

    /**
     * An endpoint as the diff tells it apart: route variables unnamed.
     */
    static String key(String endpoint) {
        return endpoint.replaceAll("\\{[^}]*}", "{}");
    }

    static String clean(String text) {
        return text == null ? "" : text.replaceAll("[\t\n\r]", " ");
    }

    private static final class Run {

        private final Path out;
        private final Set<Mutation.Operator> operators;
        private final int cap;
        private final List<Path> fixtureClasses = paths("authtracer.fixtures.classes");
        private final List<Path> libraries = paths("authtracer.fixtures.libraries");
        private final List<String> mutants = new ArrayList<>();
        private final List<String> changes = new ArrayList<>();
        private final List<String> expected = new ArrayList<>();
        private Path javaFixtures;

        Run(Path out, Set<Mutation.Operator> operators, int cap) {
            this.out = out;
            this.operators = operators;
            this.cap = cap;
            javaFixtures = fixtureClasses.stream()
                    .filter(dir -> Files.isDirectory(dir.resolve("fixtures"))
                            && dir.toString().contains(File.separator + "java" + File.separator))
                    .findFirst().orElseThrow();
        }

        MutantCompiler compiler() throws IOException {
            List<Path> classpath = new ArrayList<>(fixtureClasses);
            classpath.addAll(libraries);
            return new MutantCompiler(classpath);
        }

        /**
         * The fixture as it is and with the first mutation whose description contains {@code change}, compiled and
         * scanned.
         */
        Mutated mutated(String fixture, String change) throws IOException {
            Path packageDir = Path.of("src/fixtures/java/fixtures", fixture);
            Mutation mutation = Mutators.of(packageDir, rules(fixture)).stream()
                    .filter(candidate -> candidate.description().contains(change)).findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("No mutation of " + fixture + ": " + change));
            List<Path> files;
            try (Stream<Path> walk = Files.walk(packageDir)) {
                files = walk.filter(path -> path.toString().endsWith(".java")).sorted().toList();
            }
            Path file = packageDir.resolve(mutation.file());
            try (MutantCompiler compiler = compiler()) {
                Path others = others(fixture);
                List<ApplicationGraph> graphs = new ArrayList<>();
                for (String version : List.of("base", "mutant")) {
                    Path dir = out.resolve(version);
                    Map<Path, String> changed = version.equals("base") ? Map.of()
                            : Map.of(file, mutation.apply(Files.readString(file)));
                    compiler.compile(files, changed, dir).ifPresent(error -> {
                        throw new IllegalStateException(version + " doesn't compile: " + error);
                    });
                    graphs.add(scan(fixture, dir, others, version));
                }
                return new Mutated(graphs.getFirst(), graphs.getLast(), mutation.description());
            } finally {
                clear(out);
            }
        }

        void run(List<String> fixtures) throws IOException {
            long started = System.currentTimeMillis();
            int count = 0;
            try (MutantCompiler compiler = compiler()) {
                for (String fixture : fixtures) {
                    count += fixture(fixture, compiler);
                }
            }
            Files.createDirectories(out);
            Files.write(out.resolve("mutants.tsv"), mutants);
            Files.write(out.resolve("changes.tsv"), changes);
            Files.write(out.resolve("expected.tsv"), expected);
            System.out.printf("%d mutants of %d fixtures in %d s, written to %s%n", count, fixtures.size(),
                    (System.currentTimeMillis() - started) / 1000, out);
        }

        private int fixture(String fixture, MutantCompiler compiler) throws IOException {
            Path packageDir = Path.of("src/fixtures/java/fixtures", fixture);
            if (!Files.isDirectory(packageDir)) {
                return 0;
            }
            List<Mutation> mutations = capped(Mutators.of(packageDir, rules(fixture)), operators, cap);
            if (mutations.isEmpty()) {
                return 0;
            }
            List<Path> files;
            try (Stream<Path> walk = Files.walk(packageDir)) {
                files = walk.filter(path -> path.toString().endsWith(".java")).sorted().toList();
            }
            Path classes = out.resolve("classes").resolve(fixture);
            clear(classes);
            Path others = others(fixture);
            Path base = classes.resolve("base");
            String baseId = fixture + "/base";
            Optional<String> failed = compiler.compile(files, Map.of(), base);
            if (failed.isPresent()) {
                mutants.add(row(baseId, fixture, "-", "-", "the fixture as it is", "NOT_COMPILED", failed.get()));
                return 0;
            }
            ApplicationGraph baseGraph;
            try {
                baseGraph = scan(fixture, base, others, "base");
            } catch (RuntimeException e) {
                mutants.add(row(baseId, fixture, "-", "-", "the fixture as it is", "SCAN_FAILED", clean(e.toString())));
                return 0;
            }
            List<String> baseExpected = expectations(baseId, baseGraph);
            if (baseExpected.stream().noneMatch(line -> Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "*")
                    .contains(line.split("\t")[1]))) {
                // Nothing the harness can send a request to.
                return 0;
            }
            int differences = GraphDiff.compare(FixtureScans.scan(fixture), baseGraph).changes().size();
            mutants.add(row(baseId, fixture, "-", "-", "the fixture as it is", "BASE",
                    differences == 0 ? "" : differences + " changes from the scan of Gradle's classes"));
            expected.addAll(baseExpected);
            Map<Path, String> sources = new LinkedHashMap<>();
            for (Path file : files) {
                sources.put(file, Files.readString(file));
            }
            int n = 0;
            for (Mutation mutation : mutations) {
                String id = fixture + "/" + String.format("%03d", ++n);
                Path file = packageDir.resolve(mutation.file());
                String where = mutation.file() + ":" + mutation.line();
                Path dir = classes.resolve(String.format("%03d", n));
                Optional<String> error = compiler.compile(files, Map.of(file, mutation.apply(sources.get(file))), dir);
                if (error.isPresent()) {
                    mutants.add(row(id, fixture, mutation.operator().name(), where, mutation.description(),
                            "NOT_COMPILED", clean(error.get())));
                    continue;
                }
                ApplicationGraph graph;
                try {
                    graph = scan(fixture, dir, others, id);
                } catch (RuntimeException e) {
                    mutants.add(row(id, fixture, mutation.operator().name(), where, mutation.description(),
                            "SCAN_FAILED", clean(e.toString())));
                    continue;
                }
                DiffReport report = GraphDiff.compare(baseGraph, graph);
                for (DiffReport.Change change : report.changes()) {
                    changes.add(String.join("\t", id, change.kind().name(), change.severity().name(),
                            key(change.endpoint()), change.field(), clean(change.before()), clean(change.after())));
                }
                expected.addAll(expectations(id, graph));
                mutants.add(row(id, fixture, mutation.operator().name(), where, mutation.description(), "SCANNED",
                        report.changes().size() + " changes"));
            }
            System.out.printf("%s: %d mutants%n", fixture, mutations.size());
            return mutations.size();
        }

        private static String row(String... cells) {
            return Arrays.stream(cells).map(MutationScans::clean).collect(Collectors.joining("\t"));
        }

        /**
         * Every fixture package but this one, linked: a mutant's classes stand in for the package's own, and what
         * it refers to in other packages (generated gRPC stubs, a shared library) is still there.
         */
        private Path others(String fixture) throws IOException {
            Path root = out.resolve("others").resolve(fixture);
            Path packages = root.resolve("fixtures");
            if (Files.isDirectory(packages)) {
                return root;
            }
            Files.createDirectories(packages);
            try (Stream<Path> children = Files.list(javaFixtures.resolve("fixtures"))) {
                for (Path child : children.toList()) {
                    if (!child.getFileName().toString().equals(fixture)) {
                        Files.createSymbolicLink(packages.resolve(child.getFileName().toString()), child);
                    }
                }
            }
            return root;
        }

        private ApplicationGraph scan(String fixture, Path classes, Path others, String revision) {
            // The Kotlin and Groovy fixtures' classes, and the Java ones through the mutant's.
            List<Path> dirs = new ArrayList<>(List.of(classes, others));
            fixtureClasses.stream().filter(dir -> !dir.equals(javaFixtures)).forEach(dirs::add);
            Path resources = Path.of("src/fixtures/resources", fixture);
            return ProjectScans.defaultScanner().scan(new ScanInput(fixture, revision, dirs, libraries,
                    Files.isDirectory(resources) ? List.of(resources) : List.of(),
                    List.of("fixtures." + fixture + "."), facts(fixture)));
        }

        /**
         * As FixtureScans reads them: the fixture's own authtracer.yaml, when it has one.
         */
        private static ProvidedFacts facts(String fixture) {
            Path file = Path.of("src/fixtures/resources", fixture, ProvidedFacts.LOCAL_FILE);
            return Files.isRegularFile(file) ? ProvidedFacts.load(Optional.of(file), Optional.empty(), fixture)
                    : ProvidedFacts.NONE;
        }

        /**
         * What the fixture's rules describe (decision 0120), which are checks to mutate.
         */
        private static List<String> rules(String fixture) {
            return facts(fixture).of(ProvidedFact.Kind.RULE).stream().map(ProvidedFact::subject).toList();
        }

        private static void clear(Path dir) throws IOException {
            if (!Files.exists(dir)) {
                return;
            }
            try (Stream<Path> walk = Files.walk(dir)) {
                for (Path path : walk.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }

        private static List<Path> paths(String property) {
            String value = System.getProperty(property);
            if (value == null) {
                throw new IllegalStateException(property + " is not set; run through Gradle (mutationTest)");
            }
            return Arrays.stream(value.split(File.pathSeparator)).filter(entry -> !entry.isBlank()).map(Path::of)
                    .toList();
        }
    }
}
