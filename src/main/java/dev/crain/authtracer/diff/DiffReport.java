package dev.crain.authtracer.diff;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;

/**
 * The result of comparing two graphs, as findings a reviewer (or an agent) acts on.
 */
@Supports(Feature.DIFF)
public record DiffReport(String base, String head, List<Change> changes) {

    public enum Severity {
        /** Fails the check. */
        FAIL,
        /** Needs a human to look. */
        REVIEW,
        INFO
    }

    public enum Kind {
        WEAKENED(Severity.FAIL),
        DIAGONAL_ESCALATION(Severity.FAIL),
        /**
         * A field now exposed with less than a data governance policy requires (decision 0025), or an endpoint with
         * less than an endpoint policy requires (decision 0026).
         */
        POLICY_VIOLATION(Severity.FAIL),
        CHANGED(Severity.REVIEW),
        NEW_FINDING(Severity.REVIEW),
        STRENGTHENED(Severity.INFO),
        NEW_EXPOSURE(Severity.INFO),
        REMOVED(Severity.INFO);

        private final Severity severity;

        Kind(Severity severity) {
            this.severity = severity;
        }

        public Severity severity() {
            return severity;
        }
    }

    /**
     * Where in the code a change is.
     *
     * @param annotation the annotation the check is declared with ({@code @PreAuthorize}), {@code null} when it is
     *        no annotation: its line is the one a change to the check touches
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Site(String service, CodeRef code, String annotation) {

        static Site of(String service, CodeRef code) {
            return new Site(service, code, null);
        }
    }

    /**
     * @param field the JSON path, empty for the endpoint itself
     * @param site the check that changed, else the endpoint's handler; for a new finding, where it is
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record Change(Kind kind, Severity severity, String service, String endpoint, String field, String before,
            String after, List<String> labels, String message, Site site) {

        public Change {
            labels = List.copyOf(labels);
        }

        Change at(Site site) {
            return new Change(kind, severity, service, endpoint, field, before, after, labels, message, site);
        }

        static Change of(Kind kind, String service, String endpoint, String field, String before, String after,
                String message) {
            return of(kind, service, endpoint, field, before, after, List.of(), message);
        }

        static Change of(Kind kind, String service, String endpoint, String field, String before, String after,
                List<String> labels, String message) {
            return new Change(kind, kind.severity(), service, endpoint, field, before, after, labels, message, null);
        }
    }

    public DiffReport {
        changes = changes.stream().sorted(Comparator.comparing(Change::severity).thenComparing(Change::kind)
                .thenComparing(Change::service).thenComparing(Change::endpoint).thenComparing(Change::field))
                .toList();
    }

    public boolean failed(boolean failOnReview) {
        return !failing(failOnReview).isEmpty();
    }

    /**
     * The changes that fail the check: those of severity FAIL, and with {@code failOnReview} those that need review.
     */
    public List<Change> failing(boolean failOnReview) {
        return changes.stream().filter(change -> change.severity() == Severity.FAIL
                || failOnReview && change.severity() == Severity.REVIEW).toList();
    }

    public long count(Severity severity) {
        return changes.stream().filter(change -> change.severity() == severity).count();
    }

    public String markdown() {
        StringBuilder out = new StringBuilder("# AuthTracer diff\n\n");
        out.append("`").append(base).append("` → `").append(head).append("`\n\n");
        Map<Kind, Long> counts = new TreeMap<>();
        changes.forEach(change -> counts.merge(change.kind(), 1L, Long::sum));
        String result = count(Severity.FAIL) > 0 ? "**FAIL**" : count(Severity.REVIEW) > 0 ? "**Needs review**"
                : "**Pass**";
        out.append("Result: ").append(result);
        if (!counts.isEmpty()) {
            out.append(" (");
            counts.forEach((kind, count) -> out.append(count).append(' ').append(kind.name().toLowerCase()
                    .replace('_', ' ')).append(", "));
            out.setLength(out.length() - 2);
            out.append(')');
        }
        out.append("\n\n");
        if (changes.isEmpty()) {
            return out.append("No authorization changes.\n").toString();
        }
        out.append("| Severity | Change | Service | Endpoint | Field | Before | After |\n");
        out.append("|---|---|---|---|---|---|---|\n");
        for (Change change : changes) {
            out.append("| ").append(change.severity()).append(" | ").append(change.kind()).append(" | ")
                    .append(Markdown.cell(change.service())).append(" | ").append(Markdown.code(change.endpoint()))
                    .append(" | ").append(change.field().isEmpty() ? "(endpoint)" : Markdown.code(change.field()))
                    .append(change.labels().isEmpty() ? "" : " " + Markdown.cell(change.labels().toString()))
                    .append(" | ").append(Markdown.cell(change.before())).append(" | ")
                    .append(Markdown.cell(change.after())).append(" |\n");
        }
        out.append('\n');
        for (Change change : changes) {
            if (change.message() != null) {
                out.append("- **").append(change.kind()).append("** ").append(change.service()).append(' ')
                        .append(change.endpoint()).append(change.field().isEmpty() ? "" : " " + change.field())
                        .append(": ").append(change.message()).append('\n');
            }
        }
        return out.toString();
    }
}
