package dev.crain.authtracer.graph;

import java.util.List;
import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Non-inferred information that changes the graph (see "Provided" in MVP.md), as it was applied to a scan.
 *
 * @param subject a field id (for {@link Kind#SENSITIVE}/{@link Kind#DECLASSIFY}), a method key
 *        ({@code Class#method(args)}, for {@link Kind#CHECK}), an ingress pattern ({@code GET /path/**}, for
 *        {@link Kind#REQUIREMENT}), a label ({@code PII}, for {@link Kind#POLICY}) or an endpoint pattern
 *        ({@code PUT /admin/**}, for {@link Kind#ENDPOINT_POLICY}), or what a {@link Kind#RULE} matches
 *        ({@code annotation com.acme.RequiresPermission}, {@code call com.acme.Guard#require})
 * @param labels for a {@link Kind#RULE}, {@code [all]} when every value of a placeholder with several is needed
 * @param origin where the fact came from; when facts conflict, {@link Origin#ORG_OVERRIDE} beats {@link Origin#ORG}
 *        beats {@link Origin#LOCAL}
 * @param fresh for an {@link Kind#ENDPOINT_POLICY}: the requirement must also be checked against a live authority
 *        source somewhere on the request's chain; {@code null} otherwise
 */
@Supports({Feature.PROVIDED_FACTS, Feature.POLICIES, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ProvidedFact(Kind kind, String subject, List<String> labels, String requirement, String reason,
        Origin origin, Boolean fresh) {

    public enum Kind {
        /** The field holds sensitive data; derived fields inherit the labels. */
        SENSITIVE,
        /** The derived field no longer inherits its sources' sensitivity and requirements. */
        DECLASSIFY,
        /** A reviewed hand-rolled check, treated as a recognized Authorization Location. */
        CHECK,
        /** A requirement enforced outside the code, e.g. at the network, on matching ingress. */
        REQUIREMENT,
        /** Fields with the label must require at least this wherever they are exposed (decision 0025). */
        POLICY,
        /**
         * Matching endpoints must check this on entry, and against a live authority source if fresh (decision 0026).
         */
        ENDPOINT_POLICY,
        /**
         * Decision 0120: an authorization library's check, by its shape: an annotation, or a call to one of its
         * methods; the requirement is a template over the annotation's attributes or the call's arguments.
         */
        RULE
    }

    public enum Origin {
        LOCAL, ORG, ORG_OVERRIDE
    }

    public ProvidedFact {
        labels = labels == null ? List.of() : List.copyOf(labels);
    }

    public ProvidedFact(Kind kind, String subject, List<String> labels, String requirement, String reason,
            Origin origin) {
        this(kind, subject, labels, requirement, reason, origin, null);
    }

    /**
     * Facts about the same thing compete; sensitivity and declassification of one field are the same thing. Policies
     * don't compete: each is a floor.
     */
    public String conflictKey() {
        return (kind == Kind.SENSITIVE || kind == Kind.DECLASSIFY ? "field" : kind.name().toLowerCase(Locale.ROOT))
                + " " + subject;
    }
}
