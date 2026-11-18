package dev.crain.authtracer.conformance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.springframework.security.core.GrantedAuthority;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.abort;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

/**
 * Each fixture's graph against Spring: for every endpoint, the callers {@link Callers} makes up from what the graph
 * says it needs, sent through the booted fixture. A caller the graph lets in must not be denied, and one it keeps out
 * must be. For a response field that asks more than its endpoint, the callers {@link FieldProbes} makes up: Spring must
 * write the field for one the graph gives it to and withhold it (leave it out, write {@code null} or a masked value)
 * from one the graph keeps it from. A disagreement fails unless {@code known-differences.tsv} explains it; an answer that says neither (the
 * handler failed, the route wasn't found) and a fixture that doesn't boot are skipped, with the reason. Every probe
 * goes to {@code build/reports/conformance/results.tsv}, and the counts to {@code summary.md}. A fixture's woven
 * version ({@code aspectj+woven}) is booted from its woven classes, against the graph of those classes.
 */
class ConformanceTests {

    private static final List<String> RESULTS = Collections.synchronizedList(new ArrayList<>());
    private static final Map<String, Integer> COUNTS = Collections.synchronizedMap(new TreeMap<>());
    private static KnownDifferences known;

    @TestFactory
    Stream<DynamicNode> fixtures() throws IOException {
        Map<String, String> scanFailures = new LinkedHashMap<>();
        Map<String, Path> classes = new LinkedHashMap<>();
        Map<String, List<Expectation>> expectations = Expectation.read(
                Path.of(System.getProperty("authtracer.conformance.expected")), scanFailures, classes);
        Path resources = Path.of(System.getProperty("authtracer.conformance.resources"));
        known = KnownDifferences.load();
        Stream<DynamicNode> unscanned = scanFailures.entrySet().stream().map(failure -> dynamicTest(
                failure.getKey() + " scans", () -> fail("The scan failed: " + failure.getValue())));
        Stream<DynamicNode> probed = expectations.entrySet().stream()
                .filter(fixture -> fixture.getValue().stream().anyMatch(Expectation::http))
                .map(fixture -> dynamicContainer(fixture.getKey(), Stream.of(fixture.getKey())
                        .flatMap(name -> (classes.containsKey(name)
                                ? probeVersion(name, fixture.getValue(), resources, classes.get(name))
                                : probe(name, fixture.getValue(), resources)).stream())));
        return Stream.concat(unscanned, probed);
    }

    /**
     * Boots the fixture, sends every probe and stops it; the tests only report what happened.
     */
    private static List<DynamicTest> probe(String fixture, List<Expectation> endpoints, Path resources) {
        List<DynamicTest> tests = new ArrayList<>();
        FixtureApps.App app;
        try {
            app = FixtureApps.boot(fixture, resources);
        } catch (FixtureApps.NotBooted e) {
            count("fixture not booted");
            record("NOT_BOOTED", fixture, "-", "-", "-", "-", e.getMessage());
            tests.add(dynamicTest("boots", () -> abort(e.getMessage())));
            return tests;
        }
        try (app) {
            count("fixture booted " + (app.how().startsWith("hosted") ? "(hosted)" : "(own application)"));
            for (Expectation endpoint : endpoints) {
                if (!endpoint.http()) {
                    continue;
                }
                String untestable = Callers.untestable(endpoint);
                if (untestable != null) {
                    record("UNTESTABLE", fixture, endpoint.endpoint(), endpoint.requirement(), "-", "-", untestable);
                    tests.add(dynamicTest(endpoint.endpoint(), () -> abort(untestable)));
                    continue;
                }
                for (Callers.Probe probe : Callers.of(endpoint)) {
                    tests.add(dynamicTest(endpoint.endpoint() + " — " + probe.label(),
                            verdict(app.client().send(endpoint, probe), app.how(), endpoint, probe)));
                }
                if (!endpoint.fields().isEmpty()) {
                    tests.addAll(fields(app, endpoint));
                }
            }
        }
        return tests;
    }

    /**
     * A version of a fixture booted from classes of its own (its classes woven, {@code aspectj+woven}), in a loader
     * of its own ({@link MutantLoader}), where the probes are sent as {@link MutationProbes} takes them.
     */
    private static List<DynamicTest> probeVersion(String version, List<Expectation> endpoints, Path resources,
            Path classes) {
        List<DynamicTest> tests = new ArrayList<>();
        List<String> endpointLines = new ArrayList<>();
        List<String> probeLines = new ArrayList<>();
        List<Map.Entry<Expectation, Callers.Probe>> sent = new ArrayList<>();
        for (Expectation endpoint : endpoints) {
            if (!endpoint.http()) {
                continue;
            }
            String untestable = Callers.untestable(endpoint);
            if (untestable != null) {
                record("UNTESTABLE", version, endpoint.endpoint(), endpoint.requirement(), "-", "-", untestable);
                tests.add(dynamicTest(endpoint.endpoint(), () -> abort(untestable)));
                continue;
            }
            endpointLines.add(String.join("\t", endpoint.method(), endpoint.route(), endpoint.params()));
            for (Callers.Probe probe : Callers.of(endpoint)) {
                probeLines.add((endpointLines.size() - 1) + "\t" + (probe.caller() == null ? "anonymous"
                        : probe.caller().getAuthorities().stream().map(GrantedAuthority::getAuthority)
                                .collect(Collectors.joining(","))));
                sent.add(Map.entry(endpoint, probe));
            }
        }
        List<String> results = MutantLoader.probe(classes, version.substring(0, version.indexOf('+')), resources,
                endpointLines, probeLines);
        String[] booted = results.getFirst().split("\t", 2);
        if (!booted[0].equals("BOOTED")) {
            count("fixture not booted");
            record("NOT_BOOTED", version, "-", "-", "-", "-", booted[1]);
            tests.add(dynamicTest("boots", () -> abort(booted[1])));
            return tests;
        }
        count("fixture booted (" + version.substring(version.indexOf('+') + 1) + ")");
        String how = booted[1] + ", " + version.substring(version.indexOf('+') + 1);
        for (int i = 0; i < sent.size(); i++) {
            String[] cells = results.get(i + 1).split("\t", 2);
            Expectation endpoint = sent.get(i).getKey();
            Callers.Probe probe = sent.get(i).getValue();
            tests.add(dynamicTest(endpoint.endpoint() + " — " + probe.label(), verdict(
                    new Clients.Result(Clients.Outcome.valueOf(cells[0]), cells[1]), how, endpoint, probe)));
        }
        return tests;
    }

    /**
     * The endpoint's fields that ask more than it does: each caller {@link FieldProbes} makes up, and what Spring
     * wrote of each field for it.
     */
    private static List<DynamicTest> fields(FixtureApps.App app, Expectation endpoint) {
        List<DynamicTest> tests = new ArrayList<>();
        String untestable = FieldProbes.untestable(endpoint);
        if (untestable != null) {
            for (Expectation.Field field : endpoint.stricter()) {
                record("FIELD_UNTESTABLE", endpoint.fixture(), endpoint.endpoint() + " " + field.path(),
                        field.requirement(), "-", "-", untestable);
            }
            if (!endpoint.stricter().isEmpty()) {
                tests.add(dynamicTest(endpoint.endpoint() + " — fields", () -> abort(untestable)));
            }
            return tests;
        }
        List<FieldProbes.Caller> callers = endpoint.stricter().isEmpty()
                ? FieldProbes.callers(endpoint).subList(0, 1) : FieldProbes.callers(endpoint);
        List<Clients.Result> results = new ArrayList<>();
        for (FieldProbes.Caller caller : callers) {
            results.add(app.client().send(endpoint, caller.probe(false)));
        }
        tests.addAll(unlisted(app, endpoint, callers.getFirst(), results.getFirst()));
        if (endpoint.stricter().isEmpty()) {
            return tests;
        }
        Clients.Result again = app.client().send(endpoint, callers.getFirst().probe(false));
        for (FieldProbes.Judged judged : FieldProbes.judge(endpoint, callers, results, again)) {
            String verdict = judged.verdict();
            KnownDifferences.Entry explained = verdict.startsWith("GRAPH_")
                    ? known.find(endpoint, new Callers.Probe(judged.label(), null, false)) : null;
            String shown = endpoint.endpoint() + (judged.field() == null ? "" : " " + judged.field().path());
            record((explained != null ? "KNOWN_" : "") + "FIELD_" + verdict, endpoint.fixture(), shown,
                    judged.field() == null ? endpoint.requirement() : judged.field().requirement(), judged.label(),
                    judged.outcome(), judged.detail() + " (" + app.how() + ")");
            String message = judged.detail() + ", " + app.how();
            Executable check = switch (verdict) {
                case "AGREE" -> () -> { };
                case "INCONCLUSIVE" -> () -> abort("Can't tell what Spring wrote: " + message);
                case "RESPONSE_FAILED" -> () -> abort("Draft 0100: " + message);
                default -> explained != null ? () -> abort("Known: " + explained.reason())
                        : () -> fail("The graph says the field needs " + (judged.field() == null
                                ? "what the endpoint does" : judged.field().requirement()) + "; " + message);
            };
            tests.add(dynamicTest(shown + " — " + judged.label(), check));
        }
        return tests;
    }

    /**
     * What the response writes for the caller meeting every field that the graph lists no field for: an exposure the
     * graph doesn't show ({@code FIELD_UNLISTED}). Only a JSON body of the shape the graph says is read.
     */
    private static List<DynamicTest> unlisted(FixtureApps.App app, Expectation endpoint, FieldProbes.Caller caller,
            Clients.Result result) {
        Set<String> listed = new LinkedHashSet<>();
        for (Expectation.Field field : endpoint.fields()) {
            if (field.body().equals("view") || field.body().equals("graphql")) {
                return List.of();
            }
            listed.add(field.body());
        }
        List<String> unlisted = result.outcome() == Clients.Outcome.ALLOWED
                ? BodyFields.unlisted(result.body(), result.contentType(), listed) : null;
        if (unlisted == null) {
            return List.of();
        }
        count("field shapes read");
        List<DynamicTest> tests = new ArrayList<>();
        for (String path : unlisted) {
            String label = "unlisted " + path + ": " + caller.label();
            KnownDifferences.Entry explained = known.find(endpoint, new Callers.Probe(label, null, false));
            record((explained != null ? "KNOWN_" : "") + "FIELD_UNLISTED", endpoint.fixture(),
                    endpoint.endpoint() + " " + path, "-", label, "WRITTEN", "Spring writes " + path
                            + ", which the graph lists no field for (" + app.how() + ")");
            tests.add(dynamicTest(endpoint.endpoint() + " " + path + " — " + label, explained != null
                    ? () -> abort("Known: " + explained.reason())
                    : () -> fail("Spring writes " + path + " for " + caller.label() + ", which the graph lists no "
                            + "field for: an exposure it doesn't show, " + app.how())));
        }
        return tests;
    }

    private static Executable verdict(Clients.Result result, String how, Expectation endpoint, Callers.Probe probe) {
        Clients.Outcome outcome = result.outcome();
        String expected = probe.denied() ? "denied" : "let in";
        String verdict;
        if (outcome == Clients.Outcome.DENIED || outcome == Clients.Outcome.ALLOWED) {
            boolean denied = outcome == Clients.Outcome.DENIED;
            verdict = denied == probe.denied() ? "AGREE" : denied ? "GRAPH_WEAKER" : "GRAPH_STRICTER";
        } else {
            verdict = "INCONCLUSIVE";
        }
        KnownDifferences.Entry explained = verdict.startsWith("GRAPH_") ? known.find(endpoint, probe) : null;
        record(explained != null ? "KNOWN_" + verdict : verdict, endpoint.fixture(), endpoint.endpoint(),
                endpoint.requirement(), probe.label(), outcome.name(), result.detail() + " (" + how + ")");
        return switch (verdict) {
            case "AGREE" -> () -> { };
            case "INCONCLUSIVE" -> () -> abort("Neither denied nor let in: " + result.detail());
            default -> explained != null ? () -> abort("Known: " + explained.reason())
                    : () -> fail("The graph says " + endpoint.requirement() + ", so this caller is " + expected
                            + (verdict.equals("GRAPH_STRICTER")
                                    ? "; Spring let it in (the graph looks stricter than the application)"
                                    : "; Spring denied it (the graph looks weaker than the application)")
                            + ": " + result.detail() + ", " + how);
        };
    }

    private static void record(String verdict, String fixture, String endpoint, String requirement, String probe,
            String outcome, String detail) {
        count(verdict);
        RESULTS.add(String.join("\t", verdict, fixture, endpoint, requirement, probe, outcome, detail));
    }

    private static void count(String key) {
        COUNTS.merge(key, 1, Integer::sum);
    }

    @AfterAll
    static void report() throws IOException {
        Path dir = Path.of(System.getProperty("authtracer.conformance.report"));
        Files.createDirectories(dir);
        List<String> results = new ArrayList<>(RESULTS);
        results.sort(null);
        results.addFirst(String.join("\t", "verdict", "fixture", "endpoint", "graph requires", "caller", "outcome",
                "detail"));
        Files.write(dir.resolve("results.tsv"), results);
        List<String> summary = new ArrayList<>(List.of("# Conformance", "", "| | count |", "|---|---|"));
        COUNTS.forEach((key, count) -> summary.add("| " + key + " | " + count + " |"));
        if (known != null && !known.unused().isEmpty()) {
            summary.add("");
            summary.add("Known differences that explained nothing this run:");
            known.unused().forEach(entry -> summary.add("- " + entry.fixture() + " " + entry.endpoint() + " "
                    + entry.probe() + ": " + entry.reason()));
        }
        Files.write(dir.resolve("summary.md"), summary);
    }
}
