package dev.crain.authtracer.diff;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.diff.DiffReport.Change;

/**
 * Decision 0028: the diff for the coding agent that made the change (MVP.md: "notifying the Agent that the proposed
 * change weakens the Security Stance"): only what fails the check, grouped by the place in the code it comes from,
 * with what to do about it. Meant for an agent's hook, which feeds it back when the check fails.
 */
@Supports(Feature.AGENT_REPORT)
public final class AgentReport {

    private AgentReport() {
    }

    /**
     * @param sources each service's project directory, to name files and lines
     * @param failOnReview whether changes that need review fail the check too
     */
    public static String write(DiffReport report, Map<String, Path> sources, boolean failOnReview) {
        List<Change> failing = report.failing(failOnReview);
        if (failing.isEmpty()) {
            return "AuthTracer: no authorization got weaker.\n";
        }
        SourceFiles.ByService files = new SourceFiles.ByService(sources);
        // One item per kind, place in the code, endpoint and requirement; its fields together.
        Map<String, List<Change>> groups = new LinkedHashMap<>();
        for (Change change : failing) {
            String place = Optional.ofNullable(change.site()).map(site -> site.service() + " " + site.code())
                    .orElse("");
            groups.computeIfAbsent(String.join("|", change.kind().name(), place, change.service(), change.endpoint(),
                    String.valueOf(change.before()), String.valueOf(change.after())), key -> new ArrayList<>())
                    .add(change);
        }
        StringBuilder out = new StringBuilder("AuthTracer: this change weakens authorization, so the pull-request"
                + " check fails.\n\n");
        int number = 0;
        for (List<Change> group : groups.values()) {
            Change first = group.getFirst();
            out.append(++number).append(". ").append(sentence(first, group.stream().map(Change::field)
                    .filter(field -> !field.isEmpty()).toList())).append('\n');
            location(first, files).ifPresent(where -> out.append("   At ").append(where).append(".\n"));
        }
        out.append("\nRestore what these places required before. If the weaker requirement is intended, say so in the"
                + " pull request: it needs an Org security review.\n");
        return out.toString();
    }

    private static String sentence(Change change, List<String> fields) {
        String what = (fields.isEmpty() ? "" : (fields.size() == 1 ? "Field " : "Fields ") + String.join(", ", fields)
                + " of ") + change.service() + " " + change.endpoint();
        // A change's message names its own field; for several, what they share.
        String message = fields.size() < 2 ? change.message() : switch (change.kind()) {
            case DIAGONAL_ESCALATION -> "a new route to their data that asks less than every existing route to it";
            case WEAKENED -> "fewer callers are kept out than before";
            default -> change.message();
        };
        String because = message == null ? "" : ": " + message;
        return switch (change.kind()) {
            case WEAKENED -> what + " now requires " + change.after() + " (before: " + change.before() + ")"
                    + because + ".";
            case DIAGONAL_ESCALATION -> what + " can be read with " + change.after() + because + ".";
            case POLICY_VIOLATION -> what + " requires " + change.after() + because + ".";
            case NEW_FINDING -> "New finding in " + change.service() + because + ".";
            default -> what + ": " + change.before() + " → " + change.after() + because + ".";
        };
    }

    private static Optional<String> location(Change change, SourceFiles.ByService files) {
        return files.locate(change.site()).map(location -> location.uri() + ":" + location.line()
                + (change.site().annotation() == null ? "" : " (" + change.site().annotation() + ")"));
    }
}
