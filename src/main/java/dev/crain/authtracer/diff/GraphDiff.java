package dev.crain.authtracer.diff;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.diff.Clauses.Comparison;
import dev.crain.authtracer.diff.DiffReport.Change;
import dev.crain.authtracer.diff.DiffReport.Kind;
import dev.crain.authtracer.diff.DiffReport.Site;
import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.SystemGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compares the exposures of two versions of the same system (or service). See "Diff" in MVP.md.
 */
@Supports(Feature.DIFF)
public final class GraphDiff {

    private static final Logger LOG = LoggerFactory.getLogger(GraphDiff.class);

    /**
     * Stands for the service of a system's own finding.
     */
    static final String SYSTEM = "(system)";

    private GraphDiff() {
    }

    public static DiffReport compare(SystemGraph base, SystemGraph head) {
        List<Exposure> before = Exposures.of(base);
        List<Exposure> after = Exposures.of(head);
        Map<String, Exposure> was = index(before);
        Map<String, Exposure> now = index(after);
        List<Change> changes = new ArrayList<>(compare(before, after).stream()
                .map(change -> locate(change, was, now, base, head)).toList());
        changes.addAll(newFindings(base, head));
        changes.addAll(emptied(base, head));
        return new DiffReport(label(base), label(head), changes);
    }

    /**
     * A service whose head has no endpoint where its base had some: its scan most likely read nothing (classes or
     * packages that aren't there, a build that produced nothing), and every endpoint reads as removed, which alone
     * wouldn't fail the check. It fails: the diff can't vouch for a change it didn't see.
     */
    private static List<Change> emptied(SystemGraph base, SystemGraph head) {
        List<Change> changes = new ArrayList<>();
        for (ApplicationGraph after : head.services()) {
            long endpoints = base.services().stream().filter(before -> before.service().equals(after.service()))
                    .mapToLong(before -> before.nodes(Ingress.class).size()).sum();
            if (endpoints > 0 && after.nodes(Ingress.class).isEmpty()) {
                changes.add(new Change(Kind.REMOVED, DiffReport.Severity.FAIL, after.service(), "every endpoint", "",
                        endpoints + " endpoints", "none", List.of(), "the head's scan found no endpoint where the base"
                                + " had " + endpoints + ": it may have read nothing (classes or packages that aren't"
                                + " there, a build that produced nothing), so the diff can't vouch for the change",
                        null));
            }
        }
        return changes;
    }

    /**
     * The check that differs from before, the first on the path; else a template check that went away, where it was
     * (decision 0035: the change is in the template); else (a new endpoint, or a check that went away) the endpoint's
     * handler.
     */
    @Supports({Feature.SARIF_ANNOTATIONS, Feature.AGENT_REPORT})
    private static Change locate(Change change, Map<String, Exposure> was, Map<String, Exposure> now,
            SystemGraph base, SystemGraph head) {
        String key = Exposure.key(change.service(), change.endpoint(), change.field());
        Exposure after = now.get(key);
        Exposure before = was.get(key);
        if (after == null) {
            // Removed: every change is of an exposure the head or the base has.
            return change.at(handler(base, before));
        }
        Optional<Site> check = before == null ? Optional.empty() : after.steps().stream()
                .filter(step -> !before.steps().contains(step)).findFirst()
                .flatMap(step -> head.node(step.location()).filter(AuthorizationLocation.class::isInstance)
                        .map(AuthorizationLocation.class::cast)
                        .map(location -> new Site(SystemGraph.serviceOf(step.location()), location.target(),
                                location.mechanism().startsWith("@") ? location.mechanism() : null)));
        Optional<Site> removedFromTemplate = before == null ? Optional.empty() : before.steps().stream()
                .filter(step -> !after.steps().contains(step)).findFirst()
                .flatMap(step -> base.node(step.location()).filter(AuthorizationLocation.class::isInstance)
                        .map(AuthorizationLocation.class::cast)
                        .filter(location -> location.target() != null && location.target().className().contains("/"))
                        .map(location -> new Site(SystemGraph.serviceOf(step.location()), location.target(), null)));
        return change.at(check.or(() -> removedFromTemplate).orElseGet(() -> handler(head, after)));
    }

    private static Site handler(SystemGraph system, Exposure exposure) {
        return Site.of(exposure.service(), system.node(SystemGraph.qualify(exposure.service(), exposure.ingress()))
                .filter(Ingress.class::isInstance).map(node -> ((Ingress) node).handler()).orElse(null));
    }

    public static DiffReport compare(ApplicationGraph base, ApplicationGraph head) {
        return compare(SystemGraph.of(base), SystemGraph.of(head));
    }

    @Supports(Feature.POLICIES)
    static List<Change> compare(List<Exposure> base, List<Exposure> head) {
        Map<String, Exposure> before = index(base);
        Map<String, Exposure> after = index(head);
        List<Change> changes = new ArrayList<>();
        for (Exposure exposure : after.values()) {
            // Decision 0110: without a HEAD twin of its own, HEAD runs the GET handler under GET's rules.
            Exposure previous = Optional.ofNullable(before.get(exposure.key()))
                    .orElseGet(() -> asGet(exposure).map(before::get).orElse(null));
            for (Policies.Violation violation : exposure.violations()) {
                if (previous == null || !previous.violations().contains(violation)) {
                    changes.add(Change.of(Kind.POLICY_VIOLATION, exposure.service(), exposure.endpoint(),
                            exposure.field(), violation.requires(), exposure.requirement(), labels(exposure),
                            "the " + violation.label() + " policy requires " + violation.requires()
                                    + (violation.reason() == null ? "" : " (" + violation.reason() + ")")));
                }
            }
            if (previous == null) {
                newExposure(exposure, base).ifPresent(changes::add);
                continue;
            }
            Comparison comparison = Clauses.compare(previous.clauses(), exposure.clauses());
            switch (comparison) {
                case WEAKER -> changes.add(change(Kind.WEAKENED, exposure, previous,
                        "fewer callers are kept out than before"));
                // Decision 0106: the same text, standing for code that changed.
                case INCOMPARABLE -> changes.add(change(Kind.CHANGED, exposure, previous,
                        previous.requirement().equals(exposure.requirement())
                                ? "the code behind a requirement AuthTracer can't read changed: what it decides may have"
                                        + " too"
                                : "the requirement changed in a way that can't be ranked against the old one"));
                case STRONGER -> changes.add(change(Kind.STRENGTHENED, exposure, previous, null));
                case SAME -> {
                }
            }
        }
        for (Exposure exposure : before.values()) {
            if (after.containsKey(exposure.key())) {
                continue;
            }
            Optional<Exposure> get = asGet(exposure).map(after::get);
            if (get.isPresent()) {
                // A HEAD twin gone: HEAD now asks what GET asks.
                Optional<Kind> kind = switch (Clauses.compare(exposure.clauses(), get.get().clauses())) {
                    case WEAKER -> Optional.of(Kind.WEAKENED);
                    case STRONGER -> Optional.of(Kind.STRENGTHENED);
                    case INCOMPARABLE -> Optional.of(Kind.CHANGED);
                    case SAME -> Optional.empty();
                };
                kind.ifPresent(found -> changes.add(Change.of(found, exposure.service(), exposure.endpoint(),
                        exposure.field(), exposure.requirement(), get.get().requirement(), labels(get.get()),
                        "HEAD now runs the GET handler under GET's rules")));
                continue;
            }
            changes.add(Change.of(Kind.REMOVED, exposure.service(), exposure.endpoint(), exposure.field(),
                    exposure.requirement(), null, null));
        }
        return changes;
    }

    /**
     * The key of the GET exposure a HEAD one stands beside (decision 0110).
     */
    private static Optional<String> asGet(Exposure exposure) {
        return exposure.endpoint().startsWith("HEAD ") ? Optional.of(Exposure.key(exposure.service(),
                "GET " + exposure.endpoint().substring("HEAD ".length()), exposure.field())) : Optional.empty();
    }

    /**
     * A new route to data: a diagonal escalation when it asks less than every existing route to the same source.
     */
    @Supports(Feature.DIAGONAL_ESCALATION)
    private static Optional<Change> newExposure(Exposure exposure, List<Exposure> base) {
        if (exposure.field().isEmpty() || exposure.sources().isEmpty()) {
            return Optional.of(Change.of(Kind.NEW_EXPOSURE, exposure.service(), exposure.endpoint(),
                    exposure.field(), null, exposure.requirement(), null));
        }
        for (String source : exposure.sources()) {
            List<Exposure> existing = base.stream().filter(previous -> !previous.field().isEmpty())
                    .filter(previous -> previous.sources().contains(source)).toList();
            if (existing.isEmpty()) {
                continue;
            }
            List<Comparison> comparisons = existing.stream()
                    .map(previous -> Clauses.compare(previous.clauses(), exposure.clauses())).toList();
            // The example: an existing route no other existing route is weaker than, one of the changed service's own
            // if there is one (what its author knows), a read if there is one.
            Exposure weakest = existing.stream()
                    .filter(candidate -> existing.stream().noneMatch(other -> other != candidate
                            && Clauses.compare(candidate.clauses(), other.clauses()) == Comparison.WEAKER))
                    .min(Comparator.comparing((Exposure candidate) -> !candidate.service().equals(exposure.service()))
                            .thenComparing(candidate -> !candidate.endpoint().startsWith("GET "))
                            .thenComparingInt(candidate -> candidate.clauses().size())
                            .thenComparing(Exposure::endpoint))
                    .orElse(existing.getFirst());
            if (comparisons.stream().allMatch(comparison -> comparison == Comparison.WEAKER)) {
                return Optional.of(Change.of(Kind.DIAGONAL_ESCALATION, exposure.service(),
                        exposure.endpoint(), exposure.field(), weakest.requirement(), exposure.requirement(),
                        labels(exposure), "a new route to " + display(source)
                                + " that asks less than every existing route (e.g. "
                                + weakest.endpoint() + " " + weakest.field() + ")"));
            }
            if (comparisons.stream().noneMatch(c -> c == Comparison.SAME || c == Comparison.STRONGER)) {
                return Optional.of(Change.of(Kind.CHANGED, exposure.service(), exposure.endpoint(),
                        exposure.field(), weakest.requirement(), exposure.requirement(),
                        "a new route to " + display(source)
                                + " whose requirement can't be ranked against the existing routes"));
            }
        }
        return Optional.of(Change.of(Kind.NEW_EXPOSURE, exposure.service(), exposure.endpoint(),
                exposure.field(), null, exposure.requirement(), null));
    }

    /**
     * Findings the head has and the base doesn't: each service's, and the system's own (the linker's, about calls
     * between services), which no one service holds.
     */
    private static List<Change> newFindings(SystemGraph base, SystemGraph head) {
        Set<String> before = base.services().stream().flatMap(graph -> graph.findings().stream()
                .map(finding -> findingKey(graph.service(), finding))).collect(Collectors.toCollection(HashSet::new));
        base.findings().forEach(finding -> before.add(findingKey(SYSTEM, finding)));
        List<Change> changes = new ArrayList<>();
        for (ApplicationGraph graph : head.services()) {
            for (Finding finding : graph.findings()) {
                if (!before.contains(findingKey(graph.service(), finding))) {
                    changes.add(newFinding(graph.service(), finding));
                }
            }
        }
        head.findings().stream().filter(finding -> !before.contains(findingKey(SYSTEM, finding)))
                .forEach(finding -> changes.add(newFinding(SYSTEM, finding)));
        return changes;
    }

    private static String findingKey(String service, Finding finding) {
        return service + "|" + finding.kind() + "|" + finding.message();
    }

    private static Change newFinding(String service, Finding finding) {
        String where = finding.location() == null ? "" : finding.location().key();
        return Change.of(Kind.NEW_FINDING, service, where, "", null, finding.kind().name(), finding.message())
                .at(finding.location() == null ? null : Site.of(service, finding.location()));
    }

    private static Change change(Kind kind, Exposure exposure, Exposure previous, String message) {
        return Change.of(kind, exposure.service(), exposure.endpoint(), exposure.field(), previous.requirement(),
                exposure.requirement(), labels(exposure), message);
    }

    private static List<String> labels(Exposure exposure) {
        return exposure.labels().stream().sorted().toList();
    }

    private static Map<String, Exposure> index(List<Exposure> exposures) {
        return exposures.stream().collect(Collectors.toMap(Exposure::key, Function.identity(), (a, b) -> {
            // Two mappings that differ only in their variables' names: Spring refuses them as ambiguous.
            LOG.warn("{} and {} are one endpoint to the diff ({}); only the first is compared", a.endpoint(),
                    b.endpoint(), a.key());
            return a;
        }, LinkedHashMap::new));
    }

    private static String display(String qualifiedField) {
        return SystemGraph.serviceOf(qualifiedField) + " " + Field.shortName(SystemGraph.nodeOf(qualifiedField));
    }

    private static String label(SystemGraph system) {
        return system.services().stream().map(graph -> graph.service() + "@" + graph.revision())
                .collect(Collectors.joining(", "));
    }
}
