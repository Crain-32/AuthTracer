package dev.crain.authtracer.graph;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * A recognized, enforced authorization check: the primary node of the AuthZ graph.
 *
 * @param mechanism the catalog mechanism, e.g. {@code @PreAuthorize} or {@code authorizeHttpRequests}
 * @param target the annotated method, or the configuration method for request rules
 * @param field the protected field for {@link Scope#FIELD} checks (e.g. {@code ssn} for {@code getSsn()})
 * @param routePattern the request matcher for {@link Scope#HTTP_REQUEST} checks
 * @param denial what the caller gets when the check fails
 * @param proxied {@code true} when Spring applies the check through a proxy, so calls on {@code this} skip it
 * @param fieldOwner the class whose field a {@link Scope#FIELD} check guards, when it isn't the target's (a GraphQL
 *        resolver guards a field of the type it resolves)
 * @param freshness {@link AuthoritySource.Freshness#LIVE} when the code that decides the check reads a store or
 *        another service on every call (SRC-14), so it doesn't depend on the service's authority source alone;
 *        {@code null} when that doesn't apply
 * @param arguments EXPR-02: the method's parameters its expression names ({@code #id}), with what the request binds
 *        into them; {@code null} for none
 * @param claims EXPR-04: the token claims its expression reads ({@code principal.claims['aud']}), which are as fresh
 *        as the token; {@code null} for none
 */
@Supports(Feature.APPLICATION_GRAPH)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthorizationLocation(
        String id,
        String mechanism,
        Scope scope,
        Phase phase,
        Requirement requirement,
        CodeRef target,
        String field,
        String routePattern,
        Denial denial,
        boolean proxied,
        String fieldOwner,
        AuthoritySource.Freshness freshness,
        List<Argument> arguments,
        List<String> claims) implements Node {

    public AuthorizationLocation(String id, String mechanism, Scope scope, Phase phase, Requirement requirement,
            CodeRef target, String field, String routePattern, Denial denial, boolean proxied, String fieldOwner,
            AuthoritySource.Freshness freshness) {
        this(id, mechanism, scope, phase, requirement, target, field, routePattern, denial, proxied, fieldOwner,
                freshness, null, null);
    }

    public AuthorizationLocation(String id, String mechanism, Scope scope, Phase phase, Requirement requirement,
            CodeRef target, String field, String routePattern, Denial denial, boolean proxied) {
        this(id, mechanism, scope, phase, requirement, target, field, routePattern, denial, proxied, null);
    }

    public AuthorizationLocation(String id, String mechanism, Scope scope, Phase phase, Requirement requirement,
            CodeRef target, String field, String routePattern, Denial denial, boolean proxied, String fieldOwner) {
        this(id, mechanism, scope, phase, requirement, target, field, routePattern, denial, proxied, fieldOwner,
                null);
    }

    public AuthorizationLocation withRequirement(Requirement requirement) {
        return new AuthorizationLocation(id, mechanism, scope, phase, requirement, target, field, routePattern, denial,
                proxied, fieldOwner, freshness, arguments, claims);
    }

    @Supports(Feature.AUTHORITY_SOURCE)
    public AuthorizationLocation withFreshness(AuthoritySource.Freshness freshness) {
        return new AuthorizationLocation(id, mechanism, scope, phase, requirement, target, field, routePattern, denial,
                proxied, fieldOwner, freshness, arguments, claims);
    }

    /**
     * What the check's expression reads: the method's arguments and the token's claims, each {@code null} for none.
     */
    @Supports(Feature.METHOD_SECURITY)
    public AuthorizationLocation withReads(List<Argument> arguments, List<String> claims) {
        return new AuthorizationLocation(id, mechanism, scope, phase, requirement, target, field, routePattern, denial,
                proxied, fieldOwner, freshness, arguments == null || arguments.isEmpty() ? null
                        : List.copyOf(arguments), claims == null || claims.isEmpty() ? null : List.copyOf(claims));
    }

    /**
     * The id of the Field node a {@link Scope#FIELD} check guards, else {@code null}.
     */
    @Supports(Feature.FIELD_CHECKS)
    public String guardedField() {
        return field == null ? null : Field.id(fieldOwner != null ? fieldOwner : target.className(), field);
    }

    /**
     * EXPR-02 (decision 0091): a method parameter a check's expression names.
     *
     * @param name as the expression names it, without the {@code #}: {@code id}, {@code p0}
     * @param parameter its index among the method's parameters; {@code null} when Spring finds no parameter of the
     *        name, so the variable is {@code null} when the check runs
     * @param binding what the request binds into it ({@code path variable id}, {@code request body},
     *        {@code the caller}), when the method is a handler or every call to it passes the same handler parameter;
     *        {@code null} when AuthTracer can't tell
     */
    @Supports(Feature.METHOD_SECURITY)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Argument(String name, Integer parameter, String binding) {

        public Argument withBinding(String binding) {
            return new Argument(name, parameter, binding);
        }
    }

    public enum Scope {
        HTTP_REQUEST, METHOD, FIELD
    }

    /**
     * When the check runs relative to the protected code.
     */
    public enum Phase {
        /** Before the method body or handler runs. */
        PRE,
        /** After the method returns, on its result. */
        POST
    }

    /**
     * @param handler the denial handler class for {@link Kind#HANDLER}
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Denial(Kind kind, String handler) {

        public static final Denial THROW = new Denial(Kind.THROW, null);

        public enum Kind {
            /** Access denied exception, the default. */
            THROW,
            /** The protected value is replaced with {@code null}. */
            NULL,
            /** A custom handler decides, typically masking the value. */
            HANDLER,
            /** {@code @PreFilter}/{@code @PostFilter}: denied elements are removed. */
            FILTER
        }
    }
}
