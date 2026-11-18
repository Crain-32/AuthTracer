package dev.crain.authtracer.graph;

import java.util.Comparator;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Something the scan wants a human to see that is not part of the graph itself.
 */
@Supports({Feature.APPLICATION_GRAPH, Feature.SYSTEM_GRAPH})
public record Finding(Kind kind, String message, CodeRef location) {

    static final Comparator<Finding> ORDER = Comparator.comparing(Finding::kind)
            .thenComparing(finding -> finding.location() == null ? "" : finding.location().key())
            .thenComparing(Finding::message);

    public enum Kind {
        /** Looks like a check but isn't enforced, e.g. method security is not enabled. Counts as No Authorization. */
        NOT_ENFORCED,
        /** Enforced in general, but skipped on this call path (e.g. self-invocation past a proxy). */
        BYPASSED,
        /** Hand-rolled check-like code outside recognized mechanisms. Counts as No Authorization. */
        UNRECOGNIZED_CHECK,
        /**
         * Code outside a filter sets the Authentication (or its authorities) itself: the checks after it see what it
         * sets, so a caller may need less than the path shows. Also a filter that authenticates after the request
         * rules, which decided for a caller who hadn't signed in.
         */
        AUTHORITIES_IN_CODE,
        /** The request path goes through code the analysis can't follow, e.g. reflection. */
        OPAQUE_CALLPATH,
        /** Security configuration the analysis can't read, e.g. a RoleHierarchy built at runtime. */
        OPAQUE_CONFIG,
        /** Spring Security evaluated a check at runtime that the static graph doesn't have. */
        RUNTIME_ONLY_CHECK,
        /** A traced call between services that matches no static egress or ingress. */
        UNMATCHED_CALL,
        /** A local Provided fact lost to an Org-level fact about the same thing. */
        PROVIDED_CONFLICT,
        /**
         * A post-phase method check runs outside the method's transaction, so it decides after the commit: a denied
         * caller gets an error, but what the method wrote is saved.
         */
        CHECK_AFTER_COMMIT,
        /**
         * A check that denies every caller because of how it is configured, e.g. {@code hasPermission(..)} with no
         * {@code PermissionEvaluator}, or an authority no request carries: what it guards can't be reached.
         */
        ALWAYS_DENIED,
        /**
         * A check that lets every caller through although it reads as if it asks for something: custom decision code
         * that always grants (permit-all in disguise), or a role check that callers who haven't signed in pass
         * because the anonymous authentication carries that role.
         */
        ALWAYS_GRANTED,
        /**
         * An endpoint a library serves that hands out secrets or control of the application (Actuator's heap dump and
         * writes, the H2 console, a config server's configuration, a Eureka server's registry) answers callers who
         * have not logged in.
         */
        OPEN_SENSITIVE_ENDPOINT,
        /**
         * A service may reject the tokens a call brings: a relayed token need only name an audience the caller
         * accepts, not one the called service does, so the call fails for callers whose token names none of its; a
         * service's own token carries only the scopes its client registration asks for, so a check on the called
         * path that asks for another denies the call, and the authorization server issues none with scopes its client
         * can't be granted.
         */
        TOKEN_REJECTED
    }
}
