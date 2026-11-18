package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Just enough of a GraphQL document to name the operation a client sends: its type and the root fields it selects.
 */
@Supports(Feature.SERVICE_CALLS)
final class GraphQlDocuments {

    private static final Set<String> OPERATIONS = Set.of("query", "mutation", "subscription");

    /**
     * @param type {@code QUERY}, {@code MUTATION} or {@code SUBSCRIPTION}
     * @param fields the root fields, in order
     * @param keys each root field's response key: its alias, else its name
     */
    record Operation(String type, List<String> fields, List<String> keys) {

        /**
         * The root field a response path (e.g. {@code person.name}, {@code people[0]}) reads, else the first.
         */
        Optional<String> field(String path) {
            if (path != null && !path.isEmpty()) {
                String key = path.split("[.\\[]", 2)[0];
                int index = keys.indexOf(key);
                if (index >= 0) {
                    return Optional.of(fields.get(index));
                }
            }
            return fields.stream().findFirst();
        }
    }

    private final List<String> tokens;
    private int next;

    private GraphQlDocuments(String document) {
        this.tokens = tokenize(document);
    }

    /**
     * The document's first operation; fragment definitions before it are skipped.
     */
    static Optional<Operation> firstOperation(String document) {
        return new GraphQlDocuments(document).operation();
    }

    private Optional<Operation> operation() {
        while (next < tokens.size()) {
            String token = tokens.get(next);
            if (token.equals("{")) {
                return Optional.of(selections("QUERY"));
            }
            if (OPERATIONS.contains(token)) {
                // query Name($id: ID!) @directive { ... }
                while (next < tokens.size() && !tokens.get(next).equals("{")) {
                    if (tokens.get(next).equals("(")) {
                        skipGroup("(", ")");
                        continue;
                    }
                    next++;
                }
                return Optional.of(selections(token.toUpperCase(Locale.ROOT)));
            }
            // fragment Name on Type { ... }; a document name or a truncated one has no selection set.
            while (next < tokens.size() && !tokens.get(next).equals("{")) {
                next++;
            }
            if (next >= tokens.size()) {
                return Optional.empty();
            }
            skipGroup("{", "}");
        }
        return Optional.empty();
    }

    /**
     * Reads the root selection set, starting at its {@code {}.
     */
    private Operation selections(String type) {
        List<String> fields = new ArrayList<>();
        List<String> keys = new ArrayList<>();
        next++;
        while (next < tokens.size() && !tokens.get(next).equals("}")) {
            String token = tokens.get(next);
            if (token.equals("...")) {
                // A fragment's fields aren't followed: `...Name`, or `... on Type { }` / `... { }`.
                next++;
                if (next < tokens.size() && !tokens.get(next).equals("on") && !tokens.get(next).equals("{")
                        && !tokens.get(next).equals("@")) {
                    next++;
                    continue;
                }
                while (next < tokens.size() && !tokens.get(next).equals("{")) {
                    next++;
                }
                if (next < tokens.size()) {
                    skipGroup("{", "}");
                }
                continue;
            }
            if (token.equals("(")) {
                skipGroup("(", ")");
                continue;
            }
            if (token.equals("{")) {
                skipGroup("{", "}");
                continue;
            }
            if (token.equals("@")) {
                next += 2;
                continue;
            }
            if (Character.isLetter(token.charAt(0)) || token.charAt(0) == '_') {
                if (next + 2 < tokens.size() && tokens.get(next + 1).equals(":")) {
                    keys.add(token);
                    fields.add(tokens.get(next + 2));
                    next += 3;
                }
                else {
                    keys.add(token);
                    fields.add(token);
                    next++;
                }
                continue;
            }
            next++;
        }
        return new Operation(type, fields, keys);
    }

    private void skipGroup(String open, String close) {
        int depth = 0;
        do {
            String token = tokens.get(next++);
            if (token.equals(open)) {
                depth++;
            }
            else if (token.equals(close)) {
                depth--;
            }
        }
        while (depth > 0 && next < tokens.size());
    }

    @Supports({Feature.SERVICE_CALLS, Feature.GRAPHQL_OPERATIONS})
    static List<String> tokenize(String document) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        while (i < document.length()) {
            char c = document.charAt(i);
            if (Character.isWhitespace(c) || c == ',') {
                i++;
            }
            else if (c == '#') {
                while (i < document.length() && document.charAt(i) != '\n') {
                    i++;
                }
            }
            else if (c == '"') {
                // A string or block string: skipped, its content says nothing about the operation.
                boolean block = document.startsWith("\"\"\"", i);
                int end = block ? document.indexOf("\"\"\"", i + 3) : i + 1;
                if (!block) {
                    while (end < document.length() && document.charAt(end) != '"') {
                        end += document.charAt(end) == '\\' ? 2 : 1;
                    }
                }
                i = end < 0 ? document.length() : end + (block ? 3 : 1);
                tokens.add("\"\"");
            }
            else if (document.startsWith("...", i)) {
                tokens.add("...");
                i += 3;
            }
            else if (Character.isLetterOrDigit(c) || c == '_' || c == '-') {
                // A name, or a number (its sign, fraction and exponent come along as one token).
                int start = i++;
                while (i < document.length() && (Character.isLetterOrDigit(document.charAt(i))
                        || document.charAt(i) == '_'
                        || document.charAt(i) == '.' && !Character.isLetter(document.charAt(start)))) {
                    i++;
                }
                tokens.add(document.substring(start, i));
            }
            else {
                tokens.add(String.valueOf(c));
                i++;
            }
        }
        return tokens;
    }
}
