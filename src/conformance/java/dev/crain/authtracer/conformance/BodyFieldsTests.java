package dev.crain.authtracer.conformance;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reading a field out of a response body, and judging what Spring wrote of it, without booting anything.
 */
class BodyFieldsTests {

    private static final String JSON = "application/json";

    @Test
    void readsObjectsByNameAndEveryElementOfAnArray() {
        String body = "{\"latest\":{\"amount\":\"10\"},\"pets\":[{\"name\":\"a\"},{\"name\":\"b\"}],\"iban\":null}";
        assertEquals(BodyFields.State.written("\"10\""), BodyFields.at(body, JSON, "latest.amount"));
        assertEquals(BodyFields.State.written("[\"a\",\"b\"]"), BodyFields.at(body, JSON, "pets[].name"));
        assertEquals(BodyFields.State.NULL, BodyFields.at(body, JSON, "iban"));
        assertEquals(BodyFields.State.ABSENT, BodyFields.at(body, JSON, "ssn"));
        assertEquals(BodyFields.State.written("[\"x\"]"),
                BodyFields.at("[{\"iban\":\"x\"}]", "application/hal+json", "[].iban"));
    }

    @Test
    void whatHoldsTheFieldBeingNullLeavesItUnwritten() {
        assertEquals(BodyFields.State.ABSENT, BodyFields.at("{\"latest\":null}", JSON, "latest.amount"));
        assertEquals(BodyFields.State.ABSENT, BodyFields.at("null", JSON, "iban"));
    }

    @Test
    void whatCantBeFoundReliablyIsUnreadable() {
        unreadable("{}", JSON, "view", "rendered page");
        unreadable("{}", JSON, "graphql", "GraphQL");
        unreadable("{\"a\":{\"k\":{\"b\":1}}}", JSON, "a.*.b", "map");
        unreadable("{}", JSON, "name (Notice)", "several types");
        unreadable("{\"x\":1}\n{\"x\":2}", "application/x-ndjson", "x", "not a JSON body");
        unreadable("data: {}", "text/event-stream", "x", "not a JSON body");
        unreadable("", JSON, "x", "no body");
        unreadable("<html/>", "text/html", "x", "not a JSON body");
        unreadable("{", JSON, "x", "isn't JSON");
        unreadable("[]", JSON, "[].x", "empty array");
        unreadable("{\"pets\":{}}", JSON, "pets[].name", "not an array");
        unreadable("{\"pets\":[{\"name\":\"a\"},{}]}", JSON, "pets[].name", "differ");
        unreadable("[1]", JSON, "x", "not an object");
    }

    @Test
    void whatTheBodyWritesThatTheGraphListsNoFieldForIsUnlisted() {
        Set<String> listed = Set.of("name", "owner", "owner.email", "pets", "pets[].name", "tags", "byId",
                "byId.*.name");
        String body = "{\"name\":\"a\",\"ssn\":\"1\",\"owner\":{\"email\":\"e\",\"phone\":\"p\"},"
                + "\"pets\":[{\"name\":\"x\",\"chip\":7}],\"tags\":{\"any\":1},\"byId\":{\"k\":{\"name\":\"n\"}}}";
        assertEquals(List.of("ssn", "owner.phone", "pets[].chip"), BodyFields.unlisted(body, JSON, listed));
        assertEquals(List.of("[].ssn"), BodyFields.unlisted("[{\"iban\":\"x\",\"ssn\":\"1\"}]", JSON,
                Set.of("[].iban")));
        // HAL's controls are the media type's: Spring Data REST writes them for every item.
        String hal = "{\"name\":\"a\",\"_links\":{\"self\":{\"href\":\"/persons/1\"}},\"ssn\":\"1\"}";
        assertEquals(List.of("ssn"), BodyFields.unlisted(hal, "application/hal+json", Set.of("name")));
        assertEquals(List.of("_links", "ssn"), BodyFields.unlisted(hal, JSON, Set.of("name")));
        // Not the graph's shape, or not JSON: nothing to say.
        assertEquals(null, BodyFields.unlisted("{\"content\":[]}", JSON, Set.of("[].iban")));
        assertEquals(null, BodyFields.unlisted("text", "text/plain", Set.of("name")));
        assertEquals(null, BodyFields.unlisted("{", JSON, Set.of("name")));
    }

    @Test
    void aFieldTheGraphKeepsFromACallerIsWithheldWhenNullAbsentOrMasked() {
        Expectation endpoint = endpoint(List.of(), field("iban", "HANDLER"));
        List<FieldProbes.Caller> callers = FieldProbes.callers(endpoint);
        assertEquals(List.of("meets every field [ROLE_ADMIN]", "lacks [ROLE_ADMIN]", "anonymous"),
                callers.stream().map(FieldProbes.Caller::label).toList());
        Clients.Result full = ok("{\"iban\":\"DE00\"}");
        assertEquals(List.of("AGREE WRITTEN", "AGREE MASKED", "INCONCLUSIVE FAILED"),
                judge(endpoint, callers, full, ok("{\"iban\":\"**00\"}")));
        assertEquals(List.of("AGREE WRITTEN", "AGREE NULL", "INCONCLUSIVE FAILED"),
                judge(endpoint, callers, full, ok("{\"iban\":null}")));
        assertEquals(List.of("AGREE WRITTEN", "GRAPH_STRICTER WRITTEN", "INCONCLUSIVE FAILED"),
                judge(endpoint, callers, full, ok("{\"iban\":\"DE00\"}")));
    }

    @Test
    void aWholeResponseFailedIsDraft0100sCaseOnlyWhereAThrowingCheckFails() {
        Clients.Result denied = new Clients.Result(Clients.Outcome.DENIED, "403");
        Clients.Result full = ok("{\"ssn\":\"1\"}");
        Expectation throwing = endpoint(List.of(), field("ssn", "THROW"));
        List<FieldProbes.Caller> callers = FieldProbes.callers(throwing).subList(0, 2);
        assertEquals(List.of("AGREE", "RESPONSE_FAILED"), verdicts(FieldProbes.judge(throwing, callers,
                List.of(full, denied), full)));
        Expectation answering = endpoint(List.of(), field("ssn", "NULL"));
        assertEquals(List.of("AGREE", "GRAPH_WEAKER"), verdicts(FieldProbes.judge(answering, callers,
                List.of(full, denied), full)));
    }

    @Test
    void aFieldWhoseOwnValueIsntKnownIsInconclusive() {
        Expectation endpoint = endpoint(List.of(new Expectation.Clause("AUTHENTICATED", Set.of())),
                field("iban", "NULL"));
        List<FieldProbes.Caller> callers = FieldProbes.callers(endpoint);
        assertEquals(2, callers.size());
        Clients.Result empty = ok("{\"iban\":null}");
        assertEquals(List.of("INCONCLUSIVE", "INCONCLUSIVE"), verdicts(FieldProbes.judge(endpoint, callers,
                List.of(empty, empty), empty)));
        Clients.Result one = ok("{\"iban\":\"1\"}");
        assertTrue(FieldProbes.judge(endpoint, callers, List.of(one, one), ok("{\"iban\":\"2\"}")).stream()
                .allMatch(judged -> judged.detail().contains("changed between two requests")));
        assertTrue(FieldProbes.untestable(endpoint(List.of(new Expectation.Clause("OPAQUE", Set.of())),
                field("iban", "NULL"))).contains("expression"));
    }

    private static List<String> judge(Expectation endpoint, List<FieldProbes.Caller> callers, Clients.Result full,
            Clients.Result lacking) {
        Clients.Result anonymous = new Clients.Result(Clients.Outcome.DENIED, "401");
        return FieldProbes.judge(endpoint, callers, List.of(full, lacking, anonymous), full).stream()
                .map(judged -> judged.verdict() + " " + judged.outcome()).toList();
    }

    private static List<String> verdicts(List<FieldProbes.Judged> judged) {
        return judged.stream().map(FieldProbes.Judged::verdict).toList();
    }

    private static void unreadable(String body, String type, String path, String why) {
        BodyFields.State state = BodyFields.at(body, type, path);
        assertEquals(BodyFields.Kind.UNREADABLE, state.kind(), path);
        assertTrue(state.reason().contains(why), state.reason());
    }

    private static Clients.Result ok(String body) {
        return new Clients.Result(Clients.Outcome.ALLOWED, "200", body, JSON);
    }

    private static Expectation.Field field(String path, String answer) {
        return new Expectation.Field(path, List.of(new Expectation.Clause("ANY", Set.of("ROLE_ADMIN"))),
                "ROLE_ADMIN", Set.of(answer), path, true);
    }

    private static Expectation endpoint(List<Expectation.Clause> clauses, Expectation.Field field) {
        return new Expectation("fixture", "GET", "/accounts", "", clauses, "none", List.of(field));
    }
}
