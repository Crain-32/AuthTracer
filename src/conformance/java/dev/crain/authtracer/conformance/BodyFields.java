package dev.crain.authtracer.conformance;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * What a response body holds at a field's JSON path ({@code latest.amount}, {@code [].iban}, {@code pets[].name}):
 * written with a value, written as {@code null}, absent, or unreadable for sure. Only what can be found reliably is
 * read: a JSON body (not a stream of them, a rendered page or a GraphQL result), objects by name and the elements of
 * a non-empty array, each of which must say the same; a map's values and a field told apart by its type (several
 * senders) are unreadable.
 */
final class BodyFields {

    enum Kind {
        WRITTEN, NULL, ABSENT, UNREADABLE
    }

    /**
     * @param value for {@link Kind#WRITTEN}, the JSON written (for an array's elements, each one's in a JSON array)
     * @param reason for {@link Kind#UNREADABLE}, why
     */
    record State(Kind kind, String value, String reason) {

        static final State NULL = new State(Kind.NULL, null, null);
        static final State ABSENT = new State(Kind.ABSENT, null, null);

        static State written(String value) {
            return new State(Kind.WRITTEN, value, null);
        }

        static State unreadable(String reason) {
            return new State(Kind.UNREADABLE, null, reason);
        }

        /**
         * Not written: {@code null}, or left out.
         */
        boolean empty() {
            return kind == Kind.NULL || kind == Kind.ABSENT;
        }

        String shown() {
            return switch (kind) {
                case WRITTEN -> "written " + (value.length() > 80 ? value.substring(0, 80) + "..." : value);
                case NULL -> "null";
                case ABSENT -> "absent";
                case UNREADABLE -> "unreadable: " + reason;
            };
        }
    }

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Set<String> HAL_CONTROLS = Set.of("_links", "_templates");

    private BodyFields() {
    }

    /**
     * @param path a JSON path from the body's root, or {@code view} or {@code graphql}
     */
    static State at(String body, String contentType, String path) {
        if (path.equals("view")) {
            return State.unreadable("a rendered page, not JSON");
        }
        if (path.equals("graphql")) {
            return State.unreadable("a GraphQL result");
        }
        if (path.contains(" (")) {
            return State.unreadable("one of several types answered at the same path");
        }
        if (path.equals("*") || path.startsWith("*.") || path.contains(".*.") || path.endsWith(".*")) {
            return State.unreadable("a map's values");
        }
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (body == null || body.isBlank()) {
            return State.unreadable("no body" + (type.isEmpty() ? "" : " (" + type + ")"));
        }
        if (!type.contains("json") || type.contains("ndjson") || type.contains("stream")) {
            return State.unreadable("not a JSON body: " + (type.isEmpty() ? "no content type" : type));
        }
        JsonNode root;
        try {
            root = JSON.readTree(body);
        } catch (JacksonException e) {
            return State.unreadable("the body isn't JSON: " + e.getOriginalMessage());
        }
        return at(root, List.of(path.split("\\.", -1)), 0);
    }

    /**
     * The JSON paths of what the body writes that the graph doesn't list: a member of an object the graph lists
     * members of (the body's root, or a field whose own fields it lists), at no path it lists. A field it lists none
     * of (a library type, a leaf, a map: {@code pets.*.name}) isn't looked into; an array's elements are. {@code null}
     * when the body isn't JSON or its shape isn't the graph's (an object where it says a list). HAL's controls
     * ({@code _links}, {@code _templates}) are the media type's, not the application's data.
     *
     * @param listed the body paths of every field the graph lists for the response ({@code [].iban} in a list)
     */
    static List<String> unlisted(String body, String contentType, Set<String> listed) {
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (body == null || body.isBlank() || !type.contains("json") || type.contains("ndjson")
                || type.contains("stream")) {
            return null;
        }
        JsonNode root;
        try {
            root = JSON.readTree(body);
        } catch (JacksonException e) {
            return null;
        }
        boolean many = listed.stream().allMatch(path -> path.startsWith("[]."));
        if (many != root.isArray() || !many && !root.isObject()) {
            return null;
        }
        List<String> unlisted = new ArrayList<>();
        walk(root, many ? "[]" : "", listed, type.contains("hal") ? HAL_CONTROLS : Set.of(), unlisted);
        return unlisted;
    }

    private static void walk(JsonNode node, String path, Set<String> listed, Set<String> controls,
            List<String> unlisted) {
        if (node.isArray()) {
            for (JsonNode element : node) {
                walk(element, path.endsWith("[]") ? path : path + "[]", listed, controls, unlisted);
            }
            return;
        }
        if (!node.isObject()) {
            return;
        }
        String prefix = path.isEmpty() ? "" : path + ".";
        boolean expanded = path.isEmpty() || path.equals("[]")
                || listed.stream().anyMatch(field -> field.startsWith(prefix));
        if (!expanded || listed.stream().anyMatch(field -> field.startsWith(prefix + "*."))) {
            return;
        }
        for (Map.Entry<String, JsonNode> member : node.properties()) {
            String child = prefix + member.getKey();
            if (controls.contains(member.getKey())) {
                continue;
            }
            if (!listed.contains(child)) {
                if (!unlisted.contains(child)) {
                    unlisted.add(child);
                }
                continue;
            }
            walk(member.getValue(), child, listed, controls, unlisted);
        }
    }

    private static State at(JsonNode node, List<String> parts, int index) {
        if (index == parts.size()) {
            return node.isNull() ? State.NULL : State.written(node.toString());
        }
        String part = parts.get(index);
        boolean many = part.endsWith("[]");
        String name = many ? part.substring(0, part.length() - 2) : part;
        JsonNode next = node;
        if (!name.isEmpty()) {
            if (node.isNull()) {
                // What holds the field is null: the field isn't written.
                return State.ABSENT;
            }
            if (!node.isObject()) {
                return State.unreadable("not an object where " + name + " should be");
            }
            if (!node.has(name)) {
                return State.ABSENT;
            }
            next = node.get(name);
        }
        if (!many) {
            return at(next, parts, index + 1);
        }
        if (next.isNull()) {
            return State.ABSENT;
        }
        if (!next.isArray()) {
            return State.unreadable("not an array where " + (name.isEmpty() ? "the body" : name) + " should be");
        }
        if (next.isEmpty()) {
            return State.unreadable("an empty array: no element to read the field in");
        }
        List<State> elements = new ArrayList<>();
        for (JsonNode element : next) {
            elements.add(at(element, parts, index + 1));
        }
        State first = elements.getFirst();
        if (elements.stream().anyMatch(state -> state.kind() == Kind.UNREADABLE)) {
            return elements.stream().filter(state -> state.kind() == Kind.UNREADABLE).findFirst().orElseThrow();
        }
        if (elements.stream().anyMatch(state -> state.kind() != first.kind())) {
            return State.unreadable("the array's elements differ: " + String.join(", ", elements.stream()
                    .map(State::shown).toList()));
        }
        if (first.kind() != Kind.WRITTEN) {
            return first;
        }
        return State.written("[" + String.join(",", elements.stream().map(State::value).toList()) + "]");
    }
}
