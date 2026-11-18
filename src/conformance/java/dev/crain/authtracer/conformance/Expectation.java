package dev.crain.authtracer.conformance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One endpoint as its fixture's graph describes it: what a caller needs to reach it, as the clauses of its exposure
 * (one line of conformanceExpectations' file), and its response fields that ask more (the lines after it).
 */
record Expectation(String fixture, String method, String route, String params, List<Clause> clauses,
        String requirement, List<Field> fields) {

    /**
     * {@code ANY} needs one of the authorities; {@code AUTHENTICATED}, {@code FULLY_AUTHENTICATED},
     * {@code REMEMBER_ME}, {@code DENY} and {@code OPAQUE} need what they say and carry none.
     */
    record Clause(String kind, Set<String> authorities) {
    }

    /**
     * A response field the graph lists.
     *
     * @param path its JSON path in the exposures ({@code latest.amount}), as the diff names it
     * @param answers how the graph says its own checks answer a caller they deny: {@code THROW} (the whole response
     *        fails, decision 0100), {@code NULL}, {@code HANDLER} (the field is answered), {@code FILTER}, {@code CALL}
     * @param body where it is in the body: a JSON path from the root ({@code [].iban}), or {@code view} or
     *        {@code graphql}
     * @param stricter its requirement is stricter than its endpoint's
     */
    record Field(String path, List<Clause> clauses, String requirement, Set<String> answers, String body,
            boolean stricter) {

        boolean throwing() {
            return answers.contains("THROW");
        }
    }

    /**
     * A field line's last cell when its requirement is stricter than its endpoint's ({@code same} otherwise).
     */
    static final String STRICTER = "stricter";
    private static final Set<String> HTTP_METHODS = Set.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
            "*");

    Expectation {
        fields = List.copyOf(fields);
    }

    Expectation(String fixture, String method, String route, String params, List<Clause> clauses,
            String requirement) {
        this(fixture, method, route, params, clauses, requirement, List.of());
    }

    /**
     * The fixtures in file order, each with its endpoints; a fixture whose scan failed has none, and its message.
     *
     * @param classes filled with the directory of each version booted from classes of its own (a woven one)
     */
    static Map<String, List<Expectation>> read(Path file, Map<String, String> scanFailures, Map<String, Path> classes)
            throws IOException {
        Map<String, List<Expectation>> byFixture = new LinkedHashMap<>();
        Expectation endpoint = null;
        List<Field> fields = new ArrayList<>();
        for (String line : Files.readAllLines(file)) {
            String[] cells = line.split("\t", -1);
            if (cells[1].equals("SCAN_FAILED")) {
                scanFailures.put(cells[0], cells[2]);
                continue;
            }
            if (cells[1].equals("CLASSES")) {
                classes.put(cells[0], Path.of(cells[2]));
                continue;
            }
            List<Clause> clauses = clauses(cells[4]);
            if (cells.length > 6) {
                fields.add(new Field(cells[6], clauses, cells[5], new LinkedHashSet<>(cells[7].isEmpty() ? List.of()
                        : List.of(cells[7].split(","))), cells[8], cells[9].equals(STRICTER)));
                continue;
            }
            add(byFixture, endpoint, fields);
            endpoint = new Expectation(cells[0], cells[1], cells[2], cells[3], clauses, cells[5]);
            fields = new ArrayList<>();
        }
        add(byFixture, endpoint, fields);
        return byFixture;
    }

    private static void add(Map<String, List<Expectation>> byFixture, Expectation endpoint, List<Field> fields) {
        if (endpoint != null) {
            byFixture.computeIfAbsent(endpoint.fixture(), fixture -> new ArrayList<>()).add(endpoint.with(fields));
        }
    }

    /**
     * {@code ANY:a|b;AUTHENTICATED} as clauses.
     */
    static List<Clause> clauses(String text) {
        List<Clause> clauses = new ArrayList<>();
        for (String clause : text.isEmpty() ? new String[0] : text.split(";")) {
            int colon = clause.indexOf(':');
            clauses.add(colon < 0 ? new Clause(clause, Set.of())
                    : new Clause(clause.substring(0, colon),
                            new LinkedHashSet<>(List.of(clause.substring(colon + 1).split("\\|")))));
        }
        return clauses;
    }

    /**
     * Whether a caller holding the authorities (none for an anonymous one) meets the clauses, {@code null} when they
     * don't say (an expression, a remember-me session).
     */
    static Boolean meets(Collection<Clause> clauses, Set<String> held, boolean anonymous) {
        Set<String> authorities = anonymous ? Set.of("ROLE_ANONYMOUS") : held;
        for (Clause clause : clauses) {
            switch (clause.kind()) {
                case "ANY" -> {
                    if (clause.authorities().stream().noneMatch(authorities::contains)) {
                        return false;
                    }
                }
                case "AUTHENTICATED", "FULLY_AUTHENTICATED" -> {
                    if (anonymous) {
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

    /**
     * The response fields whose requirement is stricter than the endpoint's.
     */
    List<Field> stricter() {
        return fields.stream().filter(Field::stricter).toList();
    }

    Expectation with(List<Field> fields) {
        return new Expectation(fixture, method, route, params, clauses, requirement, fields);
    }

    /**
     * Served over HTTP (not a GraphQL operation, a message listener or another protocol).
     */
    boolean http() {
        return HTTP_METHODS.contains(method);
    }

    String endpoint() {
        return method + " " + route + (params.isEmpty() ? "" : "?" + params);
    }
}
