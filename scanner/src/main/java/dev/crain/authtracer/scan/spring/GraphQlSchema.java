package dev.crain.authtracer.scan.spring;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.scan.ScanContext;

/**
 * Decision 0033: the object types of a Spring for GraphQL schema and the fields each one declares, from the
 * {@code .graphqls}/{@code .gqls} files under {@code spring.graphql.schema.locations} (default
 * {@code classpath:graphql/**}{@code /}). Only what decides which fields a response can hold is read: object types,
 * interfaces and their extensions, field names and their named types, and the root operation types.
 *
 * @param types each object or interface type's fields, with the named type of each (lists and non-null unwrapped)
 * @param roots the type of each operation: {@code QUERY} to {@code Query}, unless a {@code schema} block renames it
 */
@Supports({Feature.GRAPHQL_OPERATIONS, Feature.RESPONSE_FIELDS})
record GraphQlSchema(Map<String, Map<String, String>> types, Map<String, String> roots) {

    static final GraphQlSchema NONE = new GraphQlSchema(Map.of(), Map.of());

    private static final Set<String> SKIPPED = Set.of("input", "enum");

    boolean isEmpty() {
        return types.isEmpty();
    }

    static GraphQlSchema load(ScanContext context) {
        List<String> locations = Arrays.stream(context.properties().get("spring.graphql.schema.locations")
                .orElse("classpath:graphql/**/").split(",")).map(String::trim).toList();
        List<String> extensions = Arrays.stream(context.properties().get("spring.graphql.schema.file-extensions")
                .orElse(".graphqls,.gqls").split(",")).map(String::trim).toList();
        StringBuilder sdl = new StringBuilder();
        for (Path resources : context.input().resourceDirs()) {
            for (String location : locations) {
                Path dir = resources.resolve(location.replaceFirst("^classpath\\*?:", "").replace("**/", "")
                        .replace("**", ""));
                if (!Files.isDirectory(dir)) {
                    continue;
                }
                try (Stream<Path> files = Files.walk(dir)) {
                    for (Path file : files.filter(Files::isRegularFile)
                            .filter(file -> extensions.stream().anyMatch(file.toString()::endsWith)).sorted()
                            .toList()) {
                        sdl.append(Files.readString(file)).append('\n');
                    }
                }
                catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                }
            }
        }
        return sdl.isEmpty() ? NONE : parse(sdl.toString());
    }

    static GraphQlSchema parse(String sdl) {
        List<String> tokens = GraphQlDocuments.tokenize(sdl);
        Map<String, Map<String, String>> types = new LinkedHashMap<>();
        Map<String, String> roots = new HashMap<>(Map.of("QUERY", "Query", "MUTATION", "Mutation",
                "SUBSCRIPTION", "Subscription"));
        int i = 0;
        while (i < tokens.size()) {
            String token = tokens.get(i);
            if ((token.equals("type") || token.equals("interface")) && i + 1 < tokens.size()) {
                Map<String, String> fields = types.computeIfAbsent(tokens.get(i + 1), name -> new LinkedHashMap<>());
                i = body(tokens, i + 2, fields);
            }
            else if (token.equals("schema")) {
                Map<String, String> operations = new LinkedHashMap<>();
                i = body(tokens, i + 1, operations);
                operations.forEach((operation, type) -> roots.put(operation.toUpperCase(Locale.ROOT), type));
            }
            else if (SKIPPED.contains(token) || token.equals("(")) {
                // Inputs and enums declare no response fields; a directive definition's arguments could look like
                // definitions.
                i = token.equals("(") ? skip(tokens, i, "(", ")") : skipTo(tokens, i);
            }
            else {
                i++;
            }
        }
        return new GraphQlSchema(types, roots);
    }

    /**
     * Reads {@code { name(args): [Type!]! @directive ... }} into the fields, from just before the brace (past
     * {@code implements A & B} and directives); returns the index after it.
     */
    private static int body(List<String> tokens, int start, Map<String, String> fields) {
        int i = start;
        while (i < tokens.size() && !tokens.get(i).equals("{")) {
            if (tokens.get(i).equals("type") || tokens.get(i).equals("interface") || tokens.get(i).equals("extend")) {
                // A type without a body: `extend type Query @directive`.
                return i;
            }
            i = tokens.get(i).equals("(") ? skip(tokens, i, "(", ")") : i + 1;
        }
        i++;
        while (i < tokens.size() && !tokens.get(i).equals("}")) {
            String token = tokens.get(i);
            if (token.equals("\"\"") || !isName(token)) {
                i++;
                continue;
            }
            int next = i + 1;
            if (next < tokens.size() && tokens.get(next).equals("(")) {
                next = skip(tokens, next, "(", ")");
            }
            if (next >= tokens.size() || !tokens.get(next).equals(":")) {
                i = next;
                continue;
            }
            next++;
            while (next < tokens.size() && !isName(tokens.get(next))) {
                next++;
            }
            if (next < tokens.size()) {
                fields.put(token, tokens.get(next));
            }
            // Past the type's closing ] and !, and its directives.
            i = next + 1;
            while (i < tokens.size() && (tokens.get(i).equals("]") || tokens.get(i).equals("!"))) {
                i++;
            }
            while (i + 1 < tokens.size() && tokens.get(i).equals("@")) {
                i += 2;
                if (i < tokens.size() && tokens.get(i).equals("(")) {
                    i = skip(tokens, i, "(", ")");
                }
            }
        }
        return i + 1;
    }

    private static int skipTo(List<String> tokens, int start) {
        int i = start;
        while (i < tokens.size() && !tokens.get(i).equals("{")) {
            i++;
        }
        return i < tokens.size() ? skip(tokens, i, "{", "}") : i;
    }

    private static int skip(List<String> tokens, int start, String open, String close) {
        int depth = 0;
        int i = start;
        do {
            String token = tokens.get(i++);
            if (token.equals(open)) {
                depth++;
            }
            else if (token.equals(close)) {
                depth--;
            }
        }
        while (depth > 0 && i < tokens.size());
        return i;
    }

    private static boolean isName(String token) {
        return Character.isLetter(token.charAt(0)) || token.charAt(0) == '_';
    }
}
