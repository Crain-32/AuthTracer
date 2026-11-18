package dev.crain.authtracer.conformance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import dev.crain.authtracer.diff.Clauses;
import dev.crain.authtracer.diff.Clauses.Clause;
import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.scan.FixtureScans;
import dev.crain.authtracer.scan.Weaving;

/**
 * Writes what each fixture's graph says a caller needs to reach each endpoint and each of its response fields, for
 * conformanceTest to check against Spring: one line per endpoint, {@code fixture, method, route, params, clauses,
 * requirement}, tab-separated, and after it one line per response field, the same cells for the field's exposure then
 * {@code field, answers, body} and {@code stricter} when it asks more than the endpoint ({@code same} otherwise).
 * Clauses are those of the exposure ({@link Exposure#clauses()}): {@code ANY:a|b} for any of the authorities,
 * {@code AUTHENTICATED}, {@code DENY} and so on, joined with {@code ;}. A fixture whose scan fails is a line
 * {@code fixture, SCAN_FAILED, message}. A fixture in {@link #WOVEN} is also woven, and its woven version checked as
 * {@code fixture+woven}, after a line {@code fixture+woven, CLASSES, directory} naming its woven classes.
 */
public final class ConformanceExpectations {

    /**
     * What a field's line says beyond its requirement.
     */
    public static final String VIEW = "view";
    public static final String GRAPHQL = "graphql";
    public static final String STRICTER = "stricter";

    /**
     * The fixtures that leave method security to AspectJ ({@code mode = AdviceMode.ASPECTJ}), whose classes are
     * woven with Spring Security's aspects, as ajc weaves an application's, for a version of their own.
     */
    private static final List<String> WOVEN = List.of("aspectj", "aspectjlegacy");

    private ConformanceExpectations() {
    }

    /**
     * One endpoint, or one of its response fields.
     *
     * @param field the field's JSON path in the exposures ({@code latest.amount}); empty for the endpoint
     * @param answers for a field, how the graph says its own checks answer a caller they deny, the
     *        {@link AuthorizationLocation.Denial.Kind}s joined with {@code ,} ({@code THROW}: the exception fails the
     *        whole response, decision 0100; {@code NULL}, {@code HANDLER}: the field is answered); {@code CALL} for a
     *        check of a service the response came from
     * @param body where the field is in the response body: its JSON path from the body's root ({@code [].iban} in a
     *        list), {@link #VIEW} for a rendered page, {@link #GRAPHQL} for an operation's result
     * @param stricter the field's requirement is stricter than its endpoint's
     */
    public record Line(Ingress ingress, String clauses, String requirement, String field, String answers,
            String body, boolean stricter) {

        /**
         * {@code method, route, params, clauses, requirement}, and for a field {@code field, answers, body} and
         * {@code stricter} or {@code same} after {@code between}.
         */
        public List<String> cells(List<String> between) {
            List<String> cells = new ArrayList<>(List.of(ingress.httpMethod(), ingress.route(),
                    ingress.params() == null ? "" : ingress.params(), clauses, clean(requirement)));
            cells.addAll(between);
            if (!field.isEmpty()) {
                cells.addAll(List.of(field, answers, body, stricter ? STRICTER : "same"));
            }
            return cells;
        }
    }

    /**
     * @param args the file to write, and {@code all} or a comma-separated list of fixture packages
     */
    public static void main(String[] args) throws IOException {
        Path out = Path.of(args[0]);
        List<String> fixtures = args[1].equals("all") ? all() : List.of(args[1].split(","));
        List<String> lines = new ArrayList<>();
        for (String fixture : fixtures) {
            try {
                lines.addAll(lines(fixture, FixtureScans.scan(fixture)));
            } catch (RuntimeException e) {
                lines.add(String.join("\t", fixture, "SCAN_FAILED", clean(String.valueOf(e))));
            }
            if (WOVEN.contains(fixture)) {
                String version = fixture + "+woven";
                try {
                    Path classes = Weaving.weave(fixture, out.resolveSibling("woven").resolve(fixture));
                    lines.add(String.join("\t", version, "CLASSES", classes.toAbsolutePath().toString()));
                    lines.addAll(lines(version, FixtureScans.scanWoven(fixture, classes)));
                } catch (RuntimeException e) {
                    lines.add(String.join("\t", version, "SCAN_FAILED", clean(String.valueOf(e))));
                }
            }
        }
        Files.createDirectories(out.getParent());
        Files.write(out, lines);
        long endpoints = lines.stream().filter(line -> line.split("\t", -1).length == 6).count();
        System.out.println("Wrote " + endpoints + " endpoints and " + (lines.size() - endpoints)
                + " fields and failures of " + fixtures.size() + " fixtures to " + out);
    }

    static List<String> lines(String fixture, ApplicationGraph graph) {
        List<String> lines = new ArrayList<>();
        for (Line line : of(graph)) {
            List<String> cells = new ArrayList<>(List.of(fixture));
            cells.addAll(line.cells(List.of()));
            lines.add(String.join("\t", cells));
        }
        return lines;
    }

    /**
     * Each endpoint, followed by its response fields.
     */
    public static List<Line> of(ApplicationGraph graph) {
        Map<String, Ingress> ingresses = graph.nodes(Ingress.class).stream()
                .collect(Collectors.toMap(Ingress::id, Function.identity(), (a, b) -> a));
        List<Line> lines = new ArrayList<>();
        Exposure endpoint = null;
        for (Exposure exposure : Exposures.of(graph)) {
            Ingress ingress = ingresses.get(exposure.ingress());
            if (ingress == null) {
                continue;
            }
            if (exposure.field().isEmpty()) {
                endpoint = exposure;
                lines.add(new Line(ingress, clauses(exposure.clauses()), exposure.requirement(), "", "", "", false));
            } else if (endpoint != null && endpoint.ingress().equals(exposure.ingress())) {
                lines.add(new Line(ingress, clauses(exposure.clauses()), exposure.requirement(), exposure.field(),
                        answers(graph, endpoint, exposure), body(ingress, exposure.field()),
                        Clauses.compare(endpoint.clauses(), exposure.clauses()) != Clauses.Comparison.SAME));
            }
        }
        return lines;
    }

    private static String clauses(Set<Clause> of) {
        TreeSet<String> clauses = new TreeSet<>();
        for (Clause clause : of) {
            clauses.add(switch (clause.kind()) {
                case ANY -> "ANY:" + String.join("|", clause.authorities());
                default -> clause.kind().name();
            });
        }
        return String.join(";", clauses);
    }

    /**
     * How the field's own checks (those its endpoint doesn't run) answer a caller they deny.
     */
    private static String answers(ApplicationGraph graph, Exposure endpoint, Exposure field) {
        Set<String> request = endpoint.steps().stream().map(Exposures.Step::location).collect(Collectors.toSet());
        TreeSet<String> answers = new TreeSet<>();
        for (Exposures.Step step : field.steps()) {
            if (request.contains(step.location())) {
                continue;
            }
            answers.add(graph.node(SystemGraph.nodeOf(step.location()))
                    .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                    .map(location -> location.denial() == null ? AuthorizationLocation.Denial.Kind.THROW.name()
                            : location.denial().kind().name())
                    .orElse("CALL"));
        }
        return String.join(",", answers);
    }

    private static String body(Ingress ingress, String field) {
        if (ingress.graphQlOperation()) {
            return GRAPHQL;
        }
        if (ingress.response().type().startsWith("view:")) {
            return VIEW;
        }
        return (ingress.response().many() ? "[]." : "") + field;
    }

    public static String clean(String text) {
        return text == null ? "" : text.replaceAll("[\t\n\r]", " ");
    }

    private static List<String> all() throws IOException {
        TreeSet<String> names = new TreeSet<>();
        for (String language : List.of("java", "kotlin", "groovy")) {
            Path dir = Path.of("src/fixtures", language, "fixtures");
            if (Files.isDirectory(dir)) {
                try (Stream<Path> children = Files.list(dir)) {
                    children.filter(Files::isDirectory).forEach(child -> names.add(child.getFileName().toString()));
                }
            }
        }
        return List.copyOf(names);
    }
}
