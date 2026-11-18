package dev.crain.authtracer.conformance;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The field half of conformance: for an endpoint whose response has fields that ask more than it does, callers who
 * meet the endpoint and lack one of those fields' clauses, and one who meets every field (sent twice: the field's
 * value must be the same both times), and what Spring wrote of each field for each of them. A field the graph keeps
 * from a caller is withheld when Spring leaves it out, writes {@code null} or writes a value other than the one the
 * caller meeting every field gets (masked); written when Spring writes that value. A check the graph says throws fails
 * the whole response instead (draft decision 0100).
 */
final class FieldProbes {

    /**
     * @param authorities what it holds; empty for an anonymous caller, who holds nothing
     */
    record Caller(String label, Set<String> authorities, boolean anonymous) {

        Callers.Probe probe(boolean denied) {
            return new Callers.Probe(label, anonymous ? null : Callers.user(authorities), denied);
        }
    }

    /**
     * One judgement: a field for a caller, or the whole response for a caller ({@code field} {@code null}).
     *
     * @param verdict {@code AGREE}, {@code GRAPH_STRICTER} (the graph keeps the field from the caller, Spring wrote
     *        it), {@code GRAPH_WEAKER} (the graph gives it, Spring withheld it or failed the response),
     *        {@code RESPONSE_FAILED} (a check the graph says throws failed the whole response, draft 0100) or
     *        {@code INCONCLUSIVE}
     * @param outcome what Spring did: {@code WRITTEN}, {@code NULL}, {@code ABSENT}, {@code MASKED}, {@code FAILED}
     *        (the whole response denied) or the request's outcome when the handler didn't answer
     */
    record Judged(String verdict, Expectation.Field field, Caller caller, String outcome, String detail) {

        /**
         * {@code field latest.amount: lacks [ROLE_X]}, or {@code field *: ...} for the whole response; what
         * known-differences.tsv matches.
         */
        String label() {
            return "field " + (field == null ? "*" : field.path()) + ": " + caller.label();
        }
    }

    private FieldProbes() {
    }

    /**
     * Why the endpoint's fields can't be probed, or {@code null}: what reaches the endpoint can't be made up, or no
     * one does.
     */
    static String untestable(Expectation endpoint) {
        String why = Callers.untestable(endpoint);
        if (why != null) {
            return why;
        }
        return Expectation.meets(endpoint.clauses(), every(endpoint), false) == Boolean.TRUE ? null
                : "no caller reaches the endpoint";
    }

    /**
     * The one meeting every field first, then one lacking each clause of a field's that leaves the endpoint met,
     * and an anonymous one where the endpoint lets everyone in and a field doesn't.
     */
    static List<Caller> callers(Expectation endpoint) {
        Set<String> every = every(endpoint);
        Map<Set<String>, Caller> callers = new LinkedHashMap<>();
        callers.put(every, new Caller("meets every field " + every, every, false));
        for (Expectation.Field field : endpoint.stricter()) {
            for (Expectation.Clause clause : field.clauses()) {
                if (!clause.kind().equals("ANY")) {
                    continue;
                }
                Set<String> held = new TreeSet<>(every);
                held.removeAll(clause.authorities());
                if (Expectation.meets(endpoint.clauses(), held, false) == Boolean.TRUE) {
                    callers.putIfAbsent(held, new Caller("lacks " + clause.authorities(), held, false));
                }
            }
        }
        if (Expectation.meets(endpoint.clauses(), Set.of(), true) == Boolean.TRUE && endpoint.stricter().stream()
                .anyMatch(field -> Expectation.meets(field.clauses(), Set.of(), true) == Boolean.FALSE)) {
            callers.put(Set.of("ROLE_ANONYMOUS"), new Caller("anonymous", Set.of(), true));
        }
        return List.copyOf(callers.values());
    }

    /**
     * Every authority the endpoint and its fields name.
     */
    private static Set<String> every(Expectation endpoint) {
        Set<String> every = new TreeSet<>();
        endpoint.clauses().forEach(clause -> every.addAll(clause.authorities()));
        endpoint.stricter().forEach(field -> field.clauses().forEach(clause -> every.addAll(clause.authorities())));
        every.remove("ROLE_ANONYMOUS");
        return every;
    }

    /**
     * @param results each caller's answer, in {@link #callers} order
     * @param again the caller meeting every field's answer to the same request, sent a second time
     */
    static List<Judged> judge(Expectation endpoint, List<Caller> callers, List<Clients.Result> results,
            Clients.Result again) {
        List<Judged> judged = new ArrayList<>();
        Clients.Result top = results.getFirst();
        for (int i = 0; i < callers.size(); i++) {
            Caller caller = callers.get(i);
            Clients.Result result = results.get(i);
            if (result.outcome() == Clients.Outcome.DENIED) {
                judged.add(failed(endpoint, caller, result));
                continue;
            }
            if (result.outcome() != Clients.Outcome.ALLOWED) {
                judged.add(new Judged("INCONCLUSIVE", null, caller, result.outcome().name(),
                        "the handler didn't answer: " + result.detail()));
                continue;
            }
            for (Expectation.Field field : endpoint.stricter()) {
                judged.add(field(field, caller, result, top, again));
            }
        }
        return judged;
    }

    /**
     * The whole response denied a caller the graph lets reach the endpoint: what draft 0100 describes when a field
     * check the caller fails throws, else the graph is weaker than Spring.
     */
    private static Judged failed(Expectation endpoint, Caller caller, Clients.Result result) {
        Set<String> throwing = new LinkedHashSet<>();
        for (Expectation.Field field : endpoint.stricter()) {
            if (field.throwing() && Expectation.meets(field.clauses(), caller.authorities(), caller.anonymous())
                    != Boolean.TRUE) {
                throwing.add(field.path());
            }
        }
        if (!throwing.isEmpty()) {
            return new Judged("RESPONSE_FAILED", null, caller, "FAILED", "the check on " + throwing
                    + " throws for this caller and fails the whole response (draft 0100): " + result.detail());
        }
        if (caller.anonymous()) {
            return new Judged("INCONCLUSIVE", null, caller, "FAILED", "Spring denied the whole response, which the "
                    + "endpoint's own anonymous caller judges: " + result.detail());
        }
        return new Judged("GRAPH_WEAKER", null, caller, "FAILED", "Spring denied the whole response; the graph lets "
                + "this caller reach the endpoint and no field check it fails throws: " + result.detail());
    }

    private static Judged field(Expectation.Field field, Caller caller, Clients.Result result, Clients.Result top,
            Clients.Result again) {
        Boolean gets = Expectation.meets(field.clauses(), caller.authorities(), caller.anonymous());
        BodyFields.State state = BodyFields.at(result.body(), result.contentType(), field.body());
        if (state.kind() == BodyFields.Kind.UNREADABLE) {
            return new Judged("INCONCLUSIVE", field, caller, "UNREADABLE", state.reason());
        }
        if (gets == null) {
            return new Judged("INCONCLUSIVE", field, caller, outcome(state, null), "the field's requirement is an "
                    + "expression or code: " + field.requirement());
        }
        BodyFields.State full = top.outcome() == Clients.Outcome.ALLOWED
                ? BodyFields.at(top.body(), top.contentType(), field.body()) : null;
        BodyFields.State fullAgain = again.outcome() == Clients.Outcome.ALLOWED
                ? BodyFields.at(again.body(), again.contentType(), field.body()) : null;
        boolean known = full != null && full.kind() == BodyFields.Kind.WRITTEN && full.equals(fullAgain);
        if (!known) {
            String why = full == null ? "the caller meeting every field was denied"
                    : full.kind() != BodyFields.Kind.WRITTEN ? "it isn't written for the caller meeting every field ("
                            + full.shown() + ")"
                    : "its value changed between two requests (" + full.shown() + "; " + (fullAgain == null
                            ? "denied" : fullAgain.shown()) + ")";
            return new Judged("INCONCLUSIVE", field, caller, outcome(state, null),
                    "can't tell the field's own value: " + why);
        }
        String outcome = outcome(state, full);
        boolean written = outcome.equals("WRITTEN");
        if (gets) {
            return written ? new Judged("AGREE", field, caller, outcome, state.shown())
                    : new Judged("GRAPH_WEAKER", field, caller, outcome, "the graph gives this caller the field, "
                            + "Spring withheld it: " + state.shown() + " (a caller meeting every field gets "
                            + full.shown() + ")");
        }
        return written ? new Judged("GRAPH_STRICTER", field, caller, outcome, "the graph keeps the field from this "
                + "caller (" + field.requirement() + "), Spring wrote it: " + state.shown())
                : new Judged("AGREE", field, caller, outcome, "withheld: " + state.shown() + answered(field, outcome));
    }

    /**
     * When Spring answers a field otherwise than the graph says its checks do.
     */
    private static String answered(Expectation.Field field, String outcome) {
        boolean graphMasks = field.answers().contains("HANDLER");
        boolean graphNulls = field.answers().contains("NULL");
        if (outcome.equals("MASKED") && !graphMasks) {
            return " (masked, where the graph says " + field.answers() + ")";
        }
        if (!outcome.equals("MASKED") && graphMasks && !graphNulls && !field.throwing()) {
            return " (not masked, where the graph says a handler answers)";
        }
        return "";
    }

    /**
     * {@code WRITTEN} when the value is the one the caller meeting every field gets, {@code MASKED} when it is
     * another.
     */
    static String outcome(BodyFields.State state, BodyFields.State full) {
        if (state.kind() != BodyFields.Kind.WRITTEN) {
            return state.kind().name();
        }
        return full == null || state.value().equals(full.value()) ? "WRITTEN" : "MASKED";
    }
}
