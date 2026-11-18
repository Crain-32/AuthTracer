package dev.crain.authtracer.conformance;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.abort;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

/**
 * The second half of {@code ./gradlew mutationTest} (mutationMutants wrote the first): boots each fixture as it is and
 * each of its mutants, sends every endpoint the same callers, and holds what Spring did against what the diff said.
 * The callers: anonymous, one with no authorities, one with each authority the graphs (the base's, a mutant's) name
 * for the endpoint, one meeting all of them and one lacking each clause. Where a graph has response fields that ask
 * more than their endpoint, also one meeting the endpoint and every such field, and that one without each of a field's
 * clauses, and with each of its alternatives instead; each response is read for those fields ({@link BodyFields}).
 *
 * <p>A mutant is <b>MISSED</b> when Spring lets in a caller it kept out before, or writes a field for a caller it
 * withheld it from (left out, {@code null}, or a value other than the one the caller meeting every field gets), and
 * the diff has nothing on that endpoint (a failing change, a change for review, or a new finding), or for a field,
 * fails neither it nor the endpoint; <b>CAUGHT</b> when the diff fails every such
 * endpoint and field it can be judged at, <b>REVIEW_ONLY</b> when it asks for review on one instead; a
 * <b>FALSE_ALARM</b> when the diff
 * fails an endpoint Spring answers every caller as before (or more strictly), or a field Spring writes for no caller
 * the change gives it to; <b>EQUIVALENT</b> when Spring lets in no one new
 * and the diff passes. <b>BLIND</b>: weaker only at endpoints whose graph already disagrees with Spring before the
 * change (a conformance disagreement: what the diff compares was wrong to begin with), which don't count against a
 * mutant the diff catches elsewhere; the graph's answer for each
 * caller is in {@code probes.tsv}. <b>UNCERTAIN</b>: a caller kept out before now gets an error instead, or one
 * whose check failed with an error before now gets in; <b>STILLBORN</b>: the
 * mutant doesn't compile or Spring refuses to boot it; <b>UNJUDGED</b>: the fixture doesn't boot, or the diff fails
 * only endpoints the harness can't send to. A miss fails unless {@code known-missed.tsv} explains it. Report:
 * {@code build/reports/mutation} ({@code results.tsv}, {@code summary.md}).
 */
@EnabledIfSystemProperty(named = "authtracer.mutation.dir", matches = ".+")
class MutationTests {

    private static final Pattern AUTHORITY = Pattern.compile("\\b(?:ROLE|SCOPE|FACTOR)_[\\w.:-]+");
    private static final Set<String> HTTP = Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "*");
    private static final List<String> RESULTS = Collections.synchronizedList(new ArrayList<>());
    private static final Map<String, Map<String, Integer>> COUNTS = new TreeMap<>();
    private static final List<String> NOTABLE = Collections.synchronizedList(new ArrayList<>());
    private static final List<String> PROBES = Collections.synchronizedList(new ArrayList<>());
    private static final Set<String> KNOWN_USED = Collections.synchronizedSet(new LinkedHashSet<>());
    private static Map<String, String> known = Map.of();

    record Mutant(String id, String fixture, String operator, String where, String description, String status,
            String detail) {
    }

    /**
     * What a graph says an endpoint needs, or one of its response fields that asks more: its clauses
     * ({@code ANY:a|b}, {@code AUTHENTICATED}, ...).
     *
     * @param field the field's JSON path as the diff names it; empty for the endpoint
     * @param body where the field is in a response body ({@link BodyFields}); empty for the endpoint
     */
    record Row(String method, String route, String params, List<String> clauses, String requirement, String key,
            String field, String body) {

        boolean http() {
            return HTTP.contains(method);
        }

        String fieldKey() {
            return key + " " + field;
        }

        String endpoint() {
            return method + " " + route + (params.isEmpty() ? "" : "?" + params);
        }
    }

    record Change(String kind, String severity, String key, String field, String before, String after) {

        String shown() {
            return kind + " " + key + (field.isEmpty() ? "" : " " + field) + ": " + before + " -> " + after;
        }
    }

    @TestFactory
    Stream<DynamicNode> mutants() throws IOException {
        Path dir = Path.of(System.getProperty("authtracer.mutation.dir"));
        Path resources = Path.of(System.getProperty("authtracer.conformance.resources"));
        known = knownMisses();
        Map<String, List<Mutant>> byFixture = new LinkedHashMap<>();
        for (String line : Files.readAllLines(dir.resolve("mutants.tsv"))) {
            String[] cells = line.split("\t", -1);
            Mutant mutant = new Mutant(cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6]);
            byFixture.computeIfAbsent(mutant.fixture(), fixture -> new ArrayList<>()).add(mutant);
        }
        Map<String, List<Row>> rows = new LinkedHashMap<>();
        for (String line : Files.readAllLines(dir.resolve("expected.tsv"))) {
            String[] cells = line.split("\t", -1);
            if (cells.length > 7 && !cells[10].equals(Expectation.STRICTER)) {
                // A field that asks what its endpoint does: the endpoint's callers judge it.
                continue;
            }
            rows.computeIfAbsent(cells[0], id -> new ArrayList<>()).add(new Row(cells[1], cells[2], cells[3],
                    cells[4].isEmpty() ? List.of() : List.of(cells[4].split(";")), cells[5], cells[6],
                    cells.length > 7 ? cells[7] : "", cells.length > 7 ? cells[9] : ""));
        }
        Map<String, List<Change>> changes = new LinkedHashMap<>();
        for (String line : Files.readAllLines(dir.resolve("changes.tsv"))) {
            String[] cells = line.split("\t", -1);
            changes.computeIfAbsent(cells[0], id -> new ArrayList<>()).add(new Change(cells[1], cells[2], cells[3],
                    cells[4], cells[5], cells[6]));
        }
        return byFixture.entrySet().stream().map(fixture -> dynamicContainer(fixture.getKey(),
                Stream.of(fixture).flatMap(entry -> new Judge(dir, resources, entry.getKey(), entry.getValue(), rows,
                        changes).tests().stream())));
    }

    private static Map<String, String> knownMisses() throws IOException {
        Map<String, String> entries = new LinkedHashMap<>();
        try (InputStream in = MutationTests.class.getResourceAsStream("/known-missed.tsv")) {
            if (in == null) {
                return entries;
            }
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().toList()) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] cells = line.split("\t", -1);
                entries.put(cells[0] + "\t" + cells[1], cells[2]);
            }
        }
        return entries;
    }

    /**
     * One fixture: its base and its mutants booted, probed and judged.
     */
    private static final class Judge {

        private final Path dir;
        private final Path resources;
        private final String fixture;
        private final List<Mutant> mutants;
        private final Map<String, List<Row>> rows;
        private final Map<String, List<Change>> changes;
        private final List<Row> endpoints;
        /**
         * For each endpoint, its response fields that ask more than it in some version (the base or a mutant), read
         * in every response to it.
         */
        private final List<List<Row>> fields = new ArrayList<>();
        private final List<String> probes = new ArrayList<>();
        /**
         * For each endpoint with such fields, the probe of the caller meeting it and every one of them: what it gets
         * of a field is the field's own value.
         */
        private final Map<Integer, Integer> topProbe = new LinkedHashMap<>();
        /**
         * The endpoints whose graph already disagrees with Spring before any change, with an example.
         */
        private final Map<String, String> disagreed = new LinkedHashMap<>();
        /**
         * The same for fields ({@link Row#fieldKey}): Spring wrote one for a caller the graph keeps it from, or the
         * other way round.
         */
        private final Map<String, String> disagreedFields = new LinkedHashMap<>();

        Judge(Path dir, Path resources, String fixture, List<Mutant> mutants, Map<String, List<Row>> rows,
                Map<String, List<Change>> changes) {
            this.dir = dir;
            this.resources = resources;
            this.fixture = fixture;
            this.mutants = mutants;
            this.rows = rows;
            this.changes = changes;
            this.endpoints = rows.getOrDefault(fixture + "/base", List.of()).stream()
                    .filter(row -> row.http() && row.field().isEmpty()).toList();
        }

        List<DynamicTest> tests() {
            List<DynamicTest> tests = new ArrayList<>();
            Mutant base = mutants.stream().filter(mutant -> mutant.id().endsWith("/base")).findFirst().orElse(null);
            if (base == null || !base.status().equals("BASE")) {
                String why = base == null ? "no base" : base.status() + " " + base.detail();
                mutants.forEach(mutant -> record("UNJUDGED", mutant, "the fixture as it is: " + why, ""));
                tests.add(dynamicTest("base", () -> abort(why)));
                return tests;
            }
            // Each authority the fixture's graph names anywhere, alone: a check the graph misplaces may ask for it.
            Set<String> named = new TreeSet<>();
            endpoints.forEach(row -> named.addAll(authorities(row)));
            for (int i = 0; i < endpoints.size(); i++) {
                Set<String> callers = new TreeSet<>(List.of("anonymous", "", MutationProbes.REMEMBERED));
                callers.addAll(named);
                String key = endpoints.get(i).key();
                List<Row> fieldRows = new ArrayList<>();
                for (Mutant mutant : mutants) {
                    rows.getOrDefault(mutant.id(), List.of()).stream().filter(row -> row.key().equals(key))
                            .forEach(row -> {
                                callers(row, callers);
                                if (!row.field().isEmpty()) {
                                    fieldRows.add(row);
                                }
                            });
                }
                Map<String, Row> byField = new LinkedHashMap<>();
                fieldRows.forEach(row -> byField.putIfAbsent(row.field(), row));
                fields.add(List.copyOf(byField.values()));
                String top = null;
                if (!byField.isEmpty()) {
                    Set<String> every = new TreeSet<>(authorities(endpoints.get(i)));
                    fieldRows.forEach(row -> every.addAll(authorities(row)));
                    top = String.join(",", every);
                    callers.add(top);
                    fieldCallers(fieldRows, every, callers);
                }
                for (String caller : callers) {
                    if (caller.equals(top)) {
                        topProbe.put(i, probes.size());
                    }
                    probes.add(i + "\t" + caller);
                }
            }
            List<String> endpointLines = new ArrayList<>();
            for (int i = 0; i < endpoints.size(); i++) {
                Row row = endpoints.get(i);
                StringBuilder line = new StringBuilder(row.method() + "\t" + row.route() + "\t" + row.params());
                fields.get(i).forEach(field -> line.append('\t').append(field.body()));
                endpointLines.add(line.toString());
            }
            List<String> before = run(classes("base"), endpointLines);
            if (!before.getFirst().startsWith("BOOTED")) {
                String why = "the fixture as it is doesn't boot: " + before.getFirst();
                mutants.stream().filter(mutant -> !mutant.id().endsWith("/base"))
                        .forEach(mutant -> record("UNJUDGED", mutant, why, ""));
                tests.add(dynamicTest("base", () -> abort(why)));
                return tests;
            }
            for (int p = 0; p < probes.size(); p++) {
                String[] probe = probes.get(p).split("\t", -1);
                int i = Integer.parseInt(probe[0]);
                Row endpoint = endpoints.get(i);
                String[] answer = before.get(p + 1).split("\t", -1);
                String outcome = answer[0];
                Boolean graph = letsIn(endpoint, probe[1]);
                PROBES.add(String.join("\t", fixture, endpoint.endpoint(), endpoint.requirement(), shown(probe[1]),
                        graph == null ? "?" : graph ? "let in" : "denied", outcome, answer[1],
                        fieldsShown(i, answer)));
                if (graph != null && (graph && outcome.equals("DENIED") || !graph && outcome.equals("ALLOWED"))) {
                    disagreed.putIfAbsent(endpoint.key(), shown(probe[1]) + ": the graph says "
                            + (graph ? "let in" : "denied") + ", Spring " + outcome);
                }
                if (outcome.equals("ALLOWED") && topProbe.containsKey(i)) {
                    baseFields(i, probe[1], answer, before.get(topProbe.get(i) + 1).split("\t", -1));
                }
            }
            for (Mutant mutant : mutants) {
                if (mutant.id().endsWith("/base")) {
                    continue;
                }
                tests.add(dynamicTest(mutant.id().substring(mutant.id().indexOf('/') + 1) + " " + mutant.operator()
                        + " " + mutant.description(), judge(mutant, before, endpointLines)));
            }
            return tests;
        }

        /**
         * The callers a field asks about, from the one meeting the endpoint and every field: without each of the
         * field's clauses, and with each of its alternatives in its place. Each still meets the other fields, so a
         * check on another field that throws doesn't fail its response (draft 0100).
         */
        private static void fieldCallers(List<Row> fieldRows, Set<String> every, Set<String> into) {
            for (Row row : fieldRows) {
                for (Set<String> clause : anyOf(row)) {
                    Set<String> without = new TreeSet<>(every);
                    without.removeAll(clause);
                    into.add(String.join(",", without));
                    for (String alternative : clause) {
                        Set<String> through = new TreeSet<>(without);
                        through.add(alternative);
                        into.add(String.join(",", through));
                    }
                }
            }
        }

        /**
         * Where the base's graph and Spring disagree on a field for a caller Spring answered: the graph gives it the
         * field and Spring withheld it, or the other way round.
         */
        private void baseFields(int i, String caller, String[] answer, String[] top) {
            Row endpoint = endpoints.get(i);
            List<Row> base = rows.getOrDefault(fixture + "/base", List.of());
            for (int j = 0; j < fields.get(i).size(); j++) {
                Row field = fields.get(i).get(j);
                String state = answer[2 + j];
                String full = top[2 + j];
                Row graphRow = base.stream().filter(row -> row.key().equals(endpoint.key())
                        && row.field().equals(field.field())).findFirst().orElse(endpoint);
                Boolean graph = letsIn(graphRow, caller);
                if (graph == null || !full.startsWith("W:") || state.startsWith("?")) {
                    continue;
                }
                boolean written = state.equals(full);
                if (graph != written) {
                    disagreedFields.putIfAbsent(field.fieldKey(), shown(caller) + ": the graph says "
                            + (graph ? "it gets " : "it doesn't get ") + field.field() + ", Spring "
                            + (written ? "wrote it" : "withheld it (" + state + ")"));
                }
            }
        }

        /**
         * Each field's state in a probe's answer, {@code field=state}.
         */
        private String fieldsShown(int i, String[] answer) {
            List<String> shown = new ArrayList<>();
            for (int j = 0; j < fields.get(i).size(); j++) {
                shown.add(fields.get(i).get(j).field() + "=" + answer[2 + j]);
            }
            return String.join("; ", shown);
        }

        private static String shown(String caller) {
            return caller.equals("anonymous") ? "anonymous" : "[" + caller + "]";
        }

        /**
         * Whether the graph's clauses let the caller in, {@code null} when they don't say (an expression).
         */
        private static Boolean letsIn(Row row, String caller) {
            boolean anonymous = caller.equals("anonymous");
            boolean remembered = caller.startsWith(MutationProbes.REMEMBERED);
            Set<String> held = anonymous ? Set.of("ROLE_ANONYMOUS") : Set.of(caller
                    .substring(remembered ? MutationProbes.REMEMBERED.length() : 0).split(","));
            for (String clause : row.clauses()) {
                int colon = clause.indexOf(':');
                String kind = colon < 0 ? clause : clause.substring(0, colon);
                switch (kind) {
                    case "ANY" -> {
                        if (Collections.disjoint(held, List.of(clause.substring(colon + 1).split("\\|")))) {
                            return false;
                        }
                    }
                    case "AUTHENTICATED" -> {
                        if (anonymous) {
                            return false;
                        }
                    }
                    case "FULLY_AUTHENTICATED" -> {
                        if (anonymous || remembered) {
                            return false;
                        }
                    }
                    case "REMEMBER_ME" -> {
                        if (!remembered) {
                            return false;
                        }
                    }
                    case "DENY" -> {
                        return false;
                    }
                    default -> {
                        return null;
                    }
                }
            }
            return true;
        }

        private Path classes(String version) {
            return dir.resolve("classes").resolve(fixture).resolve(version);
        }

        /**
         * The authorities a graph's clauses and requirement name, but {@code ROLE_ANONYMOUS}.
         */
        private static Set<String> authorities(Row row) {
            Set<String> every = new TreeSet<>();
            anyOf(row).forEach(every::addAll);
            Matcher named = AUTHORITY.matcher(row.requirement());
            while (named.find()) {
                every.add(named.group());
            }
            every.remove("ROLE_ANONYMOUS");
            return every;
        }

        private static List<Set<String>> anyOf(Row row) {
            List<Set<String>> anyOf = new ArrayList<>();
            for (String clause : row.clauses()) {
                int colon = clause.indexOf(':');
                if (colon > 0) {
                    anyOf.add(new TreeSet<>(List.of(clause.substring(colon + 1).split("\\|"))));
                }
            }
            return anyOf;
        }

        /**
         * The callers a graph's clauses call for (see the class comment): each authority alone, one meeting every
         * clause (signed in fully, and through remember-me), one meeting every clause through each one of a clause's
         * alternatives, and one lacking each clause.
         */
        private static void callers(Row row, Set<String> into) {
            Set<String> every = authorities(row);
            every.forEach(into::add);
            into.add(String.join(",", every));
            into.add(MutationProbes.REMEMBERED + String.join(",", every));
            for (Set<String> clause : anyOf(row)) {
                Set<String> without = new TreeSet<>(every);
                without.removeAll(clause);
                into.add(String.join(",", without));
                for (String alternative : clause.stream().filter(every::contains).toList()) {
                    Set<String> through = new TreeSet<>(without);
                    through.add(alternative);
                    into.add(String.join(",", through));
                }
            }
        }

        private List<String> run(Path classes, List<String> endpointLines) {
            return MutantLoader.probe(classes, fixture, resources, endpointLines, probes);
        }

        /**
         * What changed for the fields of one mutant's endpoints: the callers each field is now written for that it
         * was withheld from, the fields whose state moved, why a field couldn't be read, and for whom it was.
         */
        private final class FieldAnswers {

            final Map<String, List<String>> weaker = new LinkedHashMap<>();
            final Set<String> moved = new LinkedHashSet<>();
            final Map<String, String> unread = new LinkedHashMap<>();
            final Map<String, Set<String>> read = new LinkedHashMap<>();

            /**
             * @param b the probe's answer in the base, {@code m} in the mutant; {@code tb} and {@code tm} those of
             *        the caller meeting every field
             */
            void compare(int i, String caller, String[] b, String[] m, String[] tb, String[] tm) {
                for (int j = 0; j < fields.get(i).size(); j++) {
                    String fieldKey = fields.get(i).get(j).fieldKey();
                    String was = b[2 + j];
                    String now = m[2 + j];
                    String full = tb[2 + j];
                    String fullNow = tm[2 + j];
                    String why = !full.startsWith("W:") ? "the caller meeting every field gets " + full
                            : !full.equals(fullNow) ? "the value the caller meeting every field gets changed ("
                                    + full + " -> " + fullNow + ")"
                            : was.startsWith("?") ? was.substring(1) : now.startsWith("?") ? now.substring(1) : null;
                    if (why != null) {
                        unread.putIfAbsent(fieldKey, shown(caller) + ": " + why);
                        continue;
                    }
                    read.computeIfAbsent(fieldKey, key -> new LinkedHashSet<>()).add(caller);
                    if (!was.equals(now)) {
                        moved.add(fieldKey);
                    }
                    if (!was.equals(full) && now.equals(fullNow)) {
                        weaker.computeIfAbsent(fieldKey, key -> new ArrayList<>()).add(shown(caller));
                    }
                }
            }
        }

        private Executable judge(Mutant mutant, List<String> before, List<String> endpointLines) {
            if (!mutant.status().equals("SCANNED")) {
                record("STILLBORN", mutant, mutant.status() + ": " + mutant.detail(), "");
                return () -> abort(mutant.status() + ": " + mutant.detail());
            }
            List<Change> diff = changes.getOrDefault(mutant.id(), List.of());
            String diffShown = diff.stream().filter(change -> !change.severity().equals("INFO"))
                    .map(Change::shown).collect(Collectors.joining("; "));
            List<String> after = run(classes(mutant.id().substring(mutant.id().indexOf('/') + 1)), endpointLines);
            if (!after.getFirst().startsWith("BOOTED")) {
                record("STILLBORN", mutant, "Spring doesn't boot it: " + after.getFirst(), diffShown);
                return () -> abort("Spring doesn't boot it: " + after.getFirst());
            }
            Map<String, List<String>> weaker = new LinkedHashMap<>();
            Map<String, List<String>> uncertain = new LinkedHashMap<>();
            Set<String> moved = new LinkedHashSet<>();
            Map<String, String> unanswered = new LinkedHashMap<>();
            FieldAnswers fieldAnswers = new FieldAnswers();
            Map<String, Set<String>> callersOf = new LinkedHashMap<>();
            for (int p = 0; p < probes.size(); p++) {
                String[] probe = probes.get(p).split("\t", -1);
                int i = Integer.parseInt(probe[0]);
                Row endpoint = endpoints.get(i);
                String[] wasAnswer = before.get(p + 1).split("\t", -1);
                String[] nowAnswer = after.get(p + 1).split("\t", -1);
                String was = wasAnswer[0];
                String now = nowAnswer[0];
                String caller = shown(probe[1]);
                callersOf.computeIfAbsent(endpoint.key(), key -> new LinkedHashSet<>()).add(probe[1]);
                if (!was.equals(now)) {
                    moved.add(endpoint.key());
                }
                if (!Set.of("DENIED", "ALLOWED").contains(now)) {
                    unanswered.putIfAbsent(endpoint.key(), caller + " " + now + " " + nowAnswer[1]);
                }
                if (was.equals("DENIED") && now.equals("ALLOWED")) {
                    weaker.computeIfAbsent(endpoint.key(), key -> new ArrayList<>()).add(caller);
                } else if (was.equals("DENIED") && (now.equals("ERROR") || now.equals("UNREACHED"))
                        // A check that failed (an expression Spring can't evaluate) answered with an error before.
                        || (was.equals("ERROR") || was.equals("UNREACHED")) && now.equals("ALLOWED")) {
                    uncertain.computeIfAbsent(endpoint.key(), key -> new ArrayList<>()).add(caller + " " + was
                            + " -> " + now + " (" + nowAnswer[1] + ")");
                }
                if (was.equals("ALLOWED") && now.equals("ALLOWED") && topProbe.containsKey(i)) {
                    int top = topProbe.get(i);
                    fieldAnswers.compare(i, probe[1], wasAnswer, nowAnswer, before.get(top + 1).split("\t", -1),
                            after.get(top + 1).split("\t", -1));
                }
            }
            Map<String, Row> readFields = new LinkedHashMap<>();
            fields.forEach(list -> list.forEach(field -> readFields.put(field.fieldKey(), field)));
            Set<String> failing = diff.stream().filter(change -> change.severity().equals("FAIL"))
                    .map(Change::key).collect(Collectors.toSet());
            Set<String> review = diff.stream().filter(change -> change.kind().equals("CHANGED"))
                    .map(Change::key).collect(Collectors.toSet());
            boolean finding = diff.stream().anyMatch(change -> change.kind().equals("NEW_FINDING"));
            Map<String, List<String>> fieldWeaker = fieldAnswers.weaker;
            String spring = Stream.concat(weaker.entrySet().stream().map(entry -> entry.getKey() + " lets in "
                    + entry.getValue() + (disagreed.containsKey(entry.getKey()) ? " (before the change, "
                            + disagreed.get(entry.getKey()) + ")" : "")),
                    fieldWeaker.entrySet().stream().map(entry -> entry.getKey() + " is written for "
                            + entry.getValue() + (disagreedFields.containsKey(entry.getKey()) ? " (before the change, "
                                    + disagreedFields.get(entry.getKey()) + ")" : "")))
                    .collect(Collectors.joining("; "));
            String verdict;
            if (!weaker.isEmpty() || !fieldWeaker.isEmpty()) {
                List<String> reviewed = new ArrayList<>();
                boolean seen = false;
                boolean judged = false;
                // Where the graph already disagreed with Spring, what the diff says can't be judged: those count
                // neither for nor against the mutant.
                for (String key : weaker.keySet()) {
                    if (failing.contains(key)) {
                        judged = true;
                    } else if (!disagreed.containsKey(key)) {
                        reviewed.add(key);
                        seen |= !review.contains(key) && !finding;
                    }
                }
                for (String fieldKey : fieldWeaker.keySet()) {
                    Row field = readFields.get(fieldKey);
                    if (failsField(diff, field)) {
                        judged = true;
                    } else if (!disagreed.containsKey(field.key()) && !disagreedFields.containsKey(fieldKey)) {
                        reviewed.add(fieldKey);
                        seen |= !review.contains(field.key()) && !finding;
                    }
                }
                verdict = seen ? "MISSED" : !reviewed.isEmpty() ? "REVIEW_ONLY" : !judged ? "BLIND" : "CAUGHT";
            } else {
                // Spring's answers say whether an endpoint got weaker, and a field of its response where the field
                // can be read; not past a check the callers can't be made to pass (an expression) or where the graph
                // already disagrees with Spring.
                Set<String> probed = endpoints.stream().map(Row::key).collect(Collectors.toSet());
                Set<String> opaque = Stream.concat(endpoints.stream(), rows.getOrDefault(mutant.id(), List.of())
                        .stream()).filter(row -> row.clauses().contains("OPAQUE")).map(Row::key)
                        .collect(Collectors.toSet());
                Set<String> failingEndpoints = diff.stream().filter(change -> change.severity().equals("FAIL")
                        && change.field().isEmpty()).map(Change::key).collect(Collectors.toSet());
                List<String> alarms = failingEndpoints.stream().filter(probed::contains)
                        .filter(key -> !uncertain.containsKey(key) && !unanswered.containsKey(key)
                                && !disagreed.containsKey(key) && !opaque.contains(key)).sorted().toList();
                Map<String, String> fieldsUnjudged = new LinkedHashMap<>();
                List<String> fieldAlarms = new ArrayList<>();
                for (Change change : diff) {
                    if (!change.severity().equals("FAIL") || change.field().isEmpty()) {
                        continue;
                    }
                    String fieldKey = change.key() + " " + change.field();
                    String why = fieldUnjudged(mutant, change, readFields.get(fieldKey), fieldAnswers, probed,
                            opaque, uncertain, unanswered, callersOf);
                    if (why == null) {
                        fieldAlarms.add(fieldKey);
                    } else {
                        fieldsUnjudged.putIfAbsent(fieldKey, why);
                    }
                }
                List<String> unjudged = failing.stream().filter(unanswered::containsKey).sorted().toList();
                if (!alarms.isEmpty() || !fieldAlarms.isEmpty()) {
                    verdict = "FALSE_ALARM";
                    List<String> at = new ArrayList<>(alarms);
                    at.addAll(fieldAlarms);
                    Set<String> changed = new LinkedHashSet<>(moved);
                    changed.addAll(fieldAnswers.moved);
                    spring = "Spring lets in no one new and writes no field for anyone new at " + at
                            + (changed.isEmpty() ? " (no answer changed)"
                                    : " (answers changed at " + changed + ", none to let a caller in or write it)");
                } else if (!uncertain.isEmpty()) {
                    verdict = "UNCERTAIN";
                    spring = uncertain.entrySet().stream().map(entry -> entry.getKey() + ": " + entry.getValue())
                            .collect(Collectors.joining("; "));
                } else if (!unjudged.isEmpty()) {
                    verdict = "UNJUDGED";
                    spring = "Spring's answers don't say at " + unjudged.stream().map(key -> key + " ("
                            + unanswered.get(key) + ")").collect(Collectors.joining(", "));
                } else if (!failing.isEmpty()) {
                    verdict = "UNJUDGED";
                    spring = fieldsUnjudged.isEmpty() ? "the diff fails only what Spring's answers can't show: "
                            + "endpoints the harness doesn't send to, behind an expression, or where the graph "
                            + "already disagrees"
                            : "the diff fails fields Spring's answers can't show: " + fieldsUnjudged.entrySet()
                                    .stream().map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
                                    .collect(Collectors.joining("; "))
                                    + (failingEndpoints.isEmpty() ? "" : "; and endpoints the harness doesn't "
                                            + "send to, behind an expression, or where the graph already disagrees");
                } else {
                    verdict = "EQUIVALENT";
                    Set<String> changed = new LinkedHashSet<>(moved);
                    changed.addAll(fieldAnswers.moved);
                    spring = changed.isEmpty() ? "no answer changed" : "stricter at " + changed;
                }
            }
            String explained = verdict.equals("MISSED") ? known.get(mutant.fixture() + "\t" + mutant.description())
                    : null;
            if (explained != null) {
                KNOWN_USED.add(mutant.fixture() + "\t" + mutant.description());
            }
            record(explained != null ? "KNOWN_MISSED" : verdict, mutant, spring, diffShown);
            String message = spring + (diffShown.isEmpty() ? "; the diff says nothing" : "; the diff: " + diffShown);
            return switch (verdict) {
                case "MISSED" -> explained != null ? () -> abort("Known: " + explained)
                        : () -> fail("Spring got weaker and the diff is silent: " + message);
                case "BLIND", "FALSE_ALARM", "UNCERTAIN", "UNJUDGED" -> () -> abort(verdict + ": " + message);
                default -> () -> { };
            };
        }

        /**
         * Whether the diff fails the field, an enclosing one, or its endpoint.
         */
        private static boolean failsField(List<Change> diff, Row field) {
            return diff.stream().anyMatch(change -> change.severity().equals("FAIL")
                    && change.key().equals(field.key()) && (change.field().isEmpty()
                            || encloses(change.field(), field.field())));
        }

        private static boolean encloses(String outer, String field) {
            return field.equals(outer) || field.startsWith(outer + ".") || field.startsWith(outer + "[].")
                    || field.startsWith(outer + " (");
        }

        /**
         * Why Spring's answers can't say whether a field the diff fails got weaker, or {@code null} when they can
         * and it didn't (a false alarm): each caller the change gives the field to, as the two graphs read it, was
         * answered in both versions and the field read in both, and none of them is written it now.
         */
        private String fieldUnjudged(Mutant mutant, Change change, Row field, FieldAnswers answers,
                Set<String> probed, Set<String> opaque, Map<String, List<String>> uncertain,
                Map<String, String> unanswered, Map<String, Set<String>> callersOf) {
            String key = change.key();
            if (!probed.contains(key)) {
                return "the harness doesn't send to its endpoint";
            }
            if (field == null) {
                return "no graph says it asks more than its endpoint";
            }
            if (opaque.contains(key) || uncertain.containsKey(key) || unanswered.containsKey(key)) {
                return "its endpoint is behind an expression or answers neither way";
            }
            if (disagreed.containsKey(key) || disagreedFields.containsKey(field.fieldKey())) {
                return "the graph already disagrees with Spring there: " + disagreedFields.getOrDefault(
                        field.fieldKey(), disagreed.get(key));
            }
            if (answers.unread.containsKey(field.fieldKey())) {
                return answers.unread.get(field.fieldKey());
            }
            Row baseRow = graphRow(fixture + "/base", key, field.field());
            Row mutantRow = graphRow(mutant.id(), key, field.field());
            if (baseRow == null || mutantRow == null) {
                return "one of the graphs has no such endpoint";
            }
            List<String> gainers = callersOf.getOrDefault(key, Set.of()).stream()
                    .filter(caller -> letsIn(mutantRow, caller) == Boolean.TRUE
                            && letsIn(baseRow, caller) == Boolean.FALSE).toList();
            if (gainers.isEmpty()) {
                return "no caller sent is one the change gives the field to";
            }
            Set<String> read = answers.read.getOrDefault(field.fieldKey(), Set.of());
            List<String> unread = gainers.stream().filter(caller -> !read.contains(caller)).map(Judge::shown)
                    .toList();
            return unread.isEmpty() ? null : "the callers the change gives it to " + unread
                    + " get no response to read in one of the versions (another field's check that throws fails it, "
                    + "draft 0100)";
        }

        /**
         * What a graph says the field needs: its row, or the endpoint's when it asks no more there; {@code null}
         * when the graph has no such endpoint.
         */
        private Row graphRow(String id, String key, String field) {
            List<Row> graph = rows.getOrDefault(id, List.of());
            return graph.stream().filter(row -> row.key().equals(key) && row.field().equals(field)).findFirst()
                    .or(() -> graph.stream().filter(row -> row.key().equals(key) && row.field().isEmpty())
                            .findFirst())
                    .orElse(null);
        }
    }

    private static void record(String verdict, Mutant mutant, String spring, String diff) {
        synchronized (COUNTS) {
            COUNTS.computeIfAbsent(mutant.operator(), operator -> new TreeMap<>()).merge(verdict, 1, Integer::sum);
        }
        String line = String.join("\t", verdict, mutant.id(), mutant.operator(), mutant.where(),
                mutant.description(), spring, diff);
        RESULTS.add(line);
        if (Set.of("MISSED", "KNOWN_MISSED", "BLIND", "FALSE_ALARM", "REVIEW_ONLY", "UNCERTAIN").contains(verdict)) {
            NOTABLE.add(line);
        }
    }

    @AfterAll
    static void report() throws IOException {
        Path dir = Path.of(System.getProperty("authtracer.mutation.report"));
        Files.createDirectories(dir);
        List<String> results = new ArrayList<>(RESULTS);
        results.sort(null);
        results.addFirst(String.join("\t", "verdict", "mutant", "operator", "where", "mutation", "spring", "diff"));
        Files.write(dir.resolve("results.tsv"), results);
        List<String> probes = new ArrayList<>(PROBES);
        probes.addFirst(String.join("\t", "fixture", "endpoint", "graph requires", "caller", "graph says",
                "Spring (as it is)", "detail", "fields"));
        Files.write(dir.resolve("probes.tsv"), probes);
        Set<String> verdicts = new TreeSet<>();
        COUNTS.values().forEach(counts -> verdicts.addAll(counts.keySet()));
        List<String> summary = new ArrayList<>(List.of("# Mutation", "",
                "Each mutant: one change to a fixture's source that may weaken authorization, booted and probed "
                        + "against "
                        + "the fixture as it is, and diffed against it.", "",
                "| operator | " + String.join(" | ", verdicts) + " | total |",
                "|---|" + "---|".repeat(verdicts.size()) + "---|"));
        Map<String, Integer> totals = new TreeMap<>();
        COUNTS.forEach((operator, counts) -> {
            StringBuilder line = new StringBuilder("| " + operator + " |");
            int total = 0;
            for (String verdict : verdicts) {
                int count = counts.getOrDefault(verdict, 0);
                total += count;
                totals.merge(verdict, count, Integer::sum);
                line.append(' ').append(count == 0 ? "" : count).append(" |");
            }
            summary.add(line.append(' ').append(total).append(" |").toString());
        });
        summary.add("| **all** |" + verdicts.stream().map(verdict -> " " + totals.getOrDefault(verdict, 0) + " |")
                .collect(Collectors.joining()) + " " + totals.values().stream().mapToInt(Integer::intValue).sum()
                + " |");
        List<String> notable = new ArrayList<>(NOTABLE);
        notable.sort(null);
        for (String section : List.of("MISSED", "KNOWN_MISSED", "BLIND", "REVIEW_ONLY", "FALSE_ALARM", "UNCERTAIN")) {
            List<String> lines = notable.stream().filter(line -> line.startsWith(section + "\t")).toList();
            if (lines.isEmpty()) {
                continue;
            }
            summary.add("");
            summary.add("## " + section + " (" + lines.size() + ")");
            summary.add("");
            for (String line : lines) {
                String[] cells = line.split("\t", -1);
                summary.add("- `" + cells[1] + "` " + cells[2] + " " + cells[3] + ": " + cells[4]);
                summary.add("  - Spring: " + cells[5]);
                summary.add("  - diff: " + (cells[6].isEmpty() ? "nothing" : cells[6]));
                String reason = known.get(cells[1].substring(0, cells[1].indexOf('/')) + "\t" + cells[4]);
                if (reason != null) {
                    summary.add("  - known: " + reason);
                }
            }
        }
        List<String> unused = known.keySet().stream().filter(key -> !KNOWN_USED.contains(key)).toList();
        if (!unused.isEmpty()) {
            summary.add("");
            summary.add("Known misses that explained nothing this run:");
            unused.forEach(key -> summary.add("- " + key.replace("\t", ": ")));
        }
        Files.write(dir.resolve("summary.md"), summary);
    }
}
