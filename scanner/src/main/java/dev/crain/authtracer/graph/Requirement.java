package dev.crain.authtracer.graph;

import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * The normalized predicate an Authorization Location enforces.
 * Authorities are full names ({@code ROLE_ADMIN}, {@code SCOPE_employees.read}).
 *
 * @param expression the original expression for {@link Kind#EXPRESSION}, or the source of the whole requirement
 * @param decidedBy the application code that decides it (a custom {@code AuthorizationManager}, a SpEL bean's method, a
 *        {@code PermissionEvaluator}): an {@link Kind#EXPRESSION} when AuthTracer can't reduce what it decides, else
 *        what it was reduced to
 * @param code for an {@link Kind#EXPRESSION} that stands for code AuthTracer doesn't read (decision 0106), a digest of
 *        that code, so a change to it is a change of the requirement; {@code null} when the expression's text is all
 *        it is, and in graphs scanned before digests were recorded
 */
@Supports({Feature.REQUIREMENTS, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record Requirement(Kind kind, SortedSet<String> authorities, List<Requirement> operands, String expression,
        CodeRef decidedBy, String code) {

    public enum Kind {
        PERMIT_ALL,
        AUTHENTICATED,
        /** Authenticated, and not through remember-me: {@code fullyAuthenticated}, {@code isFullyAuthenticated()}. */
        FULLY_AUTHENTICATED,
        /** Signed in through remember-me only: {@code rememberMe}, {@code isRememberMe()}. */
        REMEMBER_ME,
        /**
         * Only callers who have not signed in: {@code anonymous()}, {@code isAnonymous()}. Anyone can be one, so it asks
         * nothing of an outsider.
         */
        ANONYMOUS,
        ANY_AUTHORITY,
        ALL_AUTHORITIES,
        DENY_ALL,
        AND,
        OR,
        NOT,
        /** Not reducible to authorities, e.g. an ownership check on {@code filterObject}. */
        EXPRESSION
    }

    public Requirement {
        authorities = authorities == null ? new TreeSet<>() : new TreeSet<>(authorities);
        operands = operands == null ? List.of() : List.copyOf(operands);
    }

    public Requirement(Kind kind, SortedSet<String> authorities, List<Requirement> operands, String expression) {
        this(kind, authorities, operands, expression, null);
    }

    public Requirement(Kind kind, SortedSet<String> authorities, List<Requirement> operands, String expression,
            CodeRef decidedBy) {
        this(kind, authorities, operands, expression, decidedBy, null);
    }

    public static Requirement permitAll() {
        return new Requirement(Kind.PERMIT_ALL, null, null, null);
    }

    public static Requirement authenticated() {
        return new Requirement(Kind.AUTHENTICATED, null, null, null);
    }

    public static Requirement fullyAuthenticated() {
        return new Requirement(Kind.FULLY_AUTHENTICATED, null, null, null);
    }

    public static Requirement rememberMe() {
        return new Requirement(Kind.REMEMBER_ME, null, null, null);
    }

    public static Requirement anonymous() {
        return new Requirement(Kind.ANONYMOUS, null, null, null);
    }

    public static Requirement denyAll() {
        return new Requirement(Kind.DENY_ALL, null, null, null);
    }

    public static Requirement anyAuthority(List<String> authorities) {
        return new Requirement(Kind.ANY_AUTHORITY, new TreeSet<>(authorities), null, null);
    }

    public static Requirement allAuthorities(List<String> authorities) {
        return new Requirement(Kind.ALL_AUTHORITIES, new TreeSet<>(authorities), null, null);
    }

    public static Requirement and(List<Requirement> operands) {
        return new Requirement(Kind.AND, null, operands, null);
    }

    public static Requirement or(List<Requirement> operands) {
        return new Requirement(Kind.OR, null, operands, null);
    }

    public static Requirement not(Requirement operand) {
        return new Requirement(Kind.NOT, null, List.of(operand), null);
    }

    public static Requirement expression(String expression) {
        return new Requirement(Kind.EXPRESSION, null, null, expression);
    }

    /**
     * What custom code decides, which AuthTracer can't reduce: {@code custom, decided by AuthorizationLogic#canRead}.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    public static Requirement custom(String expression, CodeRef decidedBy) {
        return new Requirement(Kind.EXPRESSION, null, null, expression, decidedBy);
    }

    /**
     * The same requirement, decided by this code.
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    public Requirement decidedBy(CodeRef code) {
        return new Requirement(kind, authorities, operands, expression, code, this.code);
    }

    /**
     * The same requirement, standing for code whose digest is this (decision 0106).
     */
    @Supports(Feature.CUSTOM_DECISIONS)
    public Requirement withCode(String digest) {
        return new Requirement(kind, authorities, operands, expression, decidedBy, digest);
    }

    /**
     * The same requirement with other operands, e.g. as a RoleHierarchy widens an {@code and}.
     */
    public Requirement withOperands(List<Requirement> others) {
        return new Requirement(kind, authorities, others, expression, decidedBy, code);
    }

    /**
     * The same requirement with other authorities, e.g. as a RoleHierarchy widens a role check.
     */
    public Requirement withAuthorities(SortedSet<String> others) {
        return new Requirement(kind, others, operands, expression, decidedBy, code);
    }

    /**
     * Whether anyone passes: {@code permitAll}, requirements that all do ({@code AND}), or alternatives one of which
     * does ({@code OR}, e.g. a Split whose weakest branch permits anyone).
     */
    public boolean permitsAnyone() {
        return switch (kind) {
            case PERMIT_ALL -> true;
            case AND -> operands.stream().allMatch(Requirement::permitsAnyone);
            case OR -> operands.stream().anyMatch(Requirement::permitsAnyone);
            default -> false;
        };
    }

    /**
     * Keeps the original source text alongside the normalized form.
     */
    public Requirement withSource(String source) {
        return kind == Kind.EXPRESSION ? this : new Requirement(kind, authorities, operands, source, decidedBy, code);
    }
}
