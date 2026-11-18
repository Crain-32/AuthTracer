package dev.crain.authtracer.diff;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Requirement;

/**
 * Requirements as a conjunction of clauses, so two can be ranked: {@code denyAll} > specific authorities >
 * {@code authenticated} > {@code permitAll}/none (see "Diff" in MVP.md), with {@code fullyAuthenticated} and
 * {@code rememberMe} (decision 0105: remember-me sessions only) each above {@code authenticated}, and neither above
 * the other.
 */
@Supports({Feature.DIFF, Feature.POLICIES, Feature.EXPOSURES})
public final class Clauses {

    /**
     * One condition a caller must meet.
     *
     * @param authorities for {@link Kind#ANY}: any one of these
     * @param expression for {@link Kind#OPAQUE}: the requirement as text, compared as such
     * @param code for {@link Kind#OPAQUE}: the digests of the code it stands for (decision 0106), compared too when
     *        both sides have them; {@code null} for none
     * @param branches for an opaque {@code or}: the clauses of each of its branches, which rank it however opaque
     *        they are (a caller who meets one branch meets the {@code or}); {@code null} for any other clause
     */
    public record Clause(Kind kind, SortedSet<String> authorities, String expression, String code,
            List<Set<Clause>> branches) {

        /**
         * {@link #FULLY_AUTHENTICATED} keeps out remember-me sessions, which {@link #AUTHENTICATED} lets in;
         * {@link #REMEMBER_ME} lets in remember-me sessions only, keeping out callers who signed in fully, so moving
         * a check from it to {@link #AUTHENTICATED} is a weakening.
         */
        public enum Kind {
            AUTHENTICATED, FULLY_AUTHENTICATED, REMEMBER_ME, ANY, DENY, OPAQUE
        }

        Clause(Kind kind, SortedSet<String> authorities, String expression) {
            this(kind, authorities, expression, null, null);
        }

        static Clause authenticated() {
            return new Clause(Kind.AUTHENTICATED, new TreeSet<>(), null);
        }

        static Clause fullyAuthenticated() {
            return new Clause(Kind.FULLY_AUTHENTICATED, new TreeSet<>(), null);
        }

        static Clause rememberMe() {
            return new Clause(Kind.REMEMBER_ME, new TreeSet<>(), null);
        }

        static Clause any(Collection<String> authorities) {
            return new Clause(Kind.ANY, new TreeSet<>(authorities), null);
        }

        static Clause deny() {
            return new Clause(Kind.DENY, new TreeSet<>(), null);
        }

        static Clause opaque(String expression, String code) {
            return new Clause(Kind.OPAQUE, new TreeSet<>(), expression, code, null);
        }

        @Override
        public String toString() {
            return switch (kind) {
                case AUTHENTICATED -> "authenticated";
                case FULLY_AUTHENTICATED -> "fullyAuthenticated";
                case REMEMBER_ME -> "rememberMe";
                case DENY -> "denyAll";
                case ANY -> authorities.size() == 1 ? authorities.first() : "any of " + authorities;
                case OPAQUE -> "expression " + expression;
            };
        }
    }

    public enum Comparison {
        SAME, STRONGER, WEAKER, INCOMPARABLE
    }

    private Clauses() {
    }

    /**
     * The clauses of requirements a caller must all meet, as the checks of one path.
     */
    public static Set<Clause> of(Collection<Requirement> requirements) {
        return new LinkedHashSet<>(conjunction(requirements));
    }

    static List<Clause> of(Requirement requirement) {
        return switch (requirement.kind()) {
            // Decision 0063: anyone can call without signing in, so anonymous() asks nothing of an outsider.
            case PERMIT_ALL, ANONYMOUS -> List.of();
            case AUTHENTICATED -> List.of(Clause.authenticated());
            case FULLY_AUTHENTICATED -> List.of(Clause.fullyAuthenticated());
            case REMEMBER_ME -> List.of(Clause.rememberMe());
            case DENY_ALL -> List.of(Clause.deny());
            case ANY_AUTHORITY -> List.of(Clause.any(requirement.authorities()));
            case ALL_AUTHORITIES -> requirement.authorities().stream().map(a -> Clause.any(List.of(a))).toList();
            case AND -> conjunction(requirement.operands());
            case OR -> or(requirement);
            case NOT, EXPRESSION -> List.of(Clause.opaque(text(requirement, false), code(requirement)));
        };
    }

    /**
     * Requirements a caller must all meet. One of them that only callers who haven't signed in meet
     * ({@code anonymous()}, which an MFA factory adds its factors to) with a clause no such caller meets admits no one:
     * {@code denyAll}.
     */
    private static List<Clause> conjunction(Collection<Requirement> requirements) {
        List<Clause> clauses = new ArrayList<>();
        requirements.forEach(requirement -> of(requirement).stream().filter(clause -> !clauses.contains(clause))
                .forEach(clauses::add));
        boolean anonymousOnly = requirements.stream().anyMatch(Clauses::anonymousOnly);
        return anonymousOnly && clauses.stream().anyMatch(clause -> !admitsAnonymous(clause))
                ? List.of(Clause.deny()) : clauses;
    }

    private static boolean anonymousOnly(Requirement requirement) {
        return requirement.kind() == Requirement.Kind.ANONYMOUS || requirement.kind() == Requirement.Kind.AND
                && requirement.operands().stream().anyMatch(Clauses::anonymousOnly);
    }

    /**
     * Whether a caller who hasn't signed in may meet the clause: one whose authorities include
     * {@code ROLE_ANONYMOUS}, and an expression, which can't be told (the weaker reading).
     */
    private static boolean admitsAnonymous(Clause clause) {
        return switch (clause.kind()) {
            case ANY -> clause.authorities().contains(ANONYMOUS);
            case OPAQUE -> true;
            case AUTHENTICATED, FULLY_AUTHENTICATED, REMEMBER_ME, DENY -> false;
        };
    }

    /**
     * The digests of the code an opaque requirement's expressions stand for, {@code null} for none.
     */
    private static String code(Requirement requirement) {
        if (!hasCode(requirement)) {
            // Nearly every requirement: nothing to collect.
            return null;
        }
        Set<String> digests = new TreeSet<>();
        collect(requirement, digests);
        return String.join("+", digests);
    }

    private static boolean hasCode(Requirement requirement) {
        if (requirement.code() != null) {
            return true;
        }
        for (Requirement operand : requirement.operands()) {
            if (hasCode(operand)) {
                return true;
            }
        }
        return false;
    }

    private static void collect(Requirement requirement, Set<String> digests) {
        if (requirement.code() != null) {
            digests.add(requirement.code());
        }
        requirement.operands().forEach(operand -> collect(operand, digests));
    }

    /**
     * An {@code or} is its weakest branch when every other branch implies it ({@code hasRole('ADMIN') or
     * isAuthenticated()} is {@code authenticated}, anything {@code or permitAll} asks nothing); an {@code or} of
     * authority checks is one {@code ANY} over all of them; any other {@code or} is opaque.
     */
    private static List<Clause> or(Requirement requirement) {
        List<Set<Clause>> branches = requirement.operands().stream()
                .map(operand -> (Set<Clause>) new LinkedHashSet<>(of(operand))).toList();
        for (Set<Clause> branch : branches) {
            if (branches.stream().allMatch(other -> branch.stream().allMatch(clause -> implies(other, clause)))) {
                return List.copyOf(branch);
            }
        }
        Set<String> authorities = new TreeSet<>();
        for (Requirement operand : requirement.operands()) {
            List<Clause> clauses = of(operand);
            if (clauses.size() != 1 || clauses.getFirst().kind() != Clause.Kind.ANY) {
                return List.of(new Clause(Clause.Kind.OPAQUE, new TreeSet<>(), text(requirement, false),
                        code(requirement), branches));
            }
            authorities.addAll(clauses.getFirst().authorities());
        }
        return List.of(Clause.any(authorities));
    }

    /**
     * An opaque requirement as it is compared: its normalized structure, not its source. A role hierarchy or a role
     * prefix widens the operands of {@code hasRole('MANAGER') or #id == principal.id} but leaves its source as it was,
     * so comparing sources would hide the change. Only an expression the scan couldn't reduce is its own text.
     */
    private static String text(Requirement requirement, boolean nested) {
        List<String> operands = requirement.operands().stream().map(operand -> text(operand, true)).toList();
        String text = switch (requirement.kind()) {
            case PERMIT_ALL -> "permitAll";
            case AUTHENTICATED -> "authenticated";
            case FULLY_AUTHENTICATED -> "fullyAuthenticated";
            case REMEMBER_ME -> "rememberMe";
            case ANONYMOUS -> "anonymous";
            case DENY_ALL -> "denyAll";
            case ANY_AUTHORITY -> requirement.authorities().size() == 1 ? requirement.authorities().first()
                    : "any of " + requirement.authorities();
            case ALL_AUTHORITIES -> requirement.authorities().size() == 1 ? requirement.authorities().first()
                    : "all of " + requirement.authorities();
            case AND -> String.join(" and ", operands);
            case OR -> String.join(" or ", operands);
            case NOT -> "not " + operands.getFirst();
            case EXPRESSION -> String.valueOf(requirement.expression());
        };
        boolean compound = requirement.kind() == Requirement.Kind.AND || requirement.kind() == Requirement.Kind.OR;
        return nested && compound ? "(" + text + ")" : text;
    }

    /**
     * Spring's AnonymousAuthenticationFilter grants this to callers who didn't sign in.
     */
    private static final String ANONYMOUS = "ROLE_ANONYMOUS";

    /**
     * Whether a clause keeps out callers who didn't sign in: an authority check does, unless anonymous callers hold
     * one of its authorities; a remember-me session has signed in.
     */
    private static boolean signedIn(Clause clause) {
        return switch (clause.kind()) {
            case AUTHENTICATED, FULLY_AUTHENTICATED, REMEMBER_ME, DENY -> true;
            case ANY -> !clause.authorities().contains(ANONYMOUS);
            case OPAQUE -> false;
        };
    }

    /**
     * Role hierarchies are already applied: the scan widens each role check to the roles that imply it.
     */
    static boolean implies(Set<Clause> held, Clause required) {
        // A caller who meets one branch of an or meets the or, whatever the other branches ask.
        if (required.branches() != null && required.branches().stream()
                .anyMatch(branch -> branch.stream().allMatch(clause -> implies(held, clause)))) {
            return true;
        }
        for (Clause clause : held) {
            if (clause.kind() == Clause.Kind.DENY) {
                return true;
            }
            // An or a caller meets by any branch asks at least what every branch asks.
            if (clause.branches() != null && clause.branches().stream().allMatch(branch -> implies(branch, required))) {
                return true;
            }
            switch (required.kind()) {
                case AUTHENTICATED -> {
                    if (signedIn(clause)) {
                        return true;
                    }
                }
                case FULLY_AUTHENTICATED -> {
                    if (clause.kind() == Clause.Kind.FULLY_AUTHENTICATED) {
                        return true;
                    }
                }
                case REMEMBER_ME -> {
                    // Only a remember-me session passes rememberMe(): a role check or a sign-in says nothing of how.
                    if (clause.kind() == Clause.Kind.REMEMBER_ME) {
                        return true;
                    }
                }
                case ANY -> {
                    if (clause.kind() == Clause.Kind.ANY && required.authorities().containsAll(clause.authorities())) {
                        return true;
                    }
                }
                case OPAQUE -> {
                    // Decision 0106: the same text standing for code that changed may decide otherwise; a graph
                    // scanned before digests were recorded has none to compare.
                    if (clause.kind() == Clause.Kind.OPAQUE && clause.expression().equals(required.expression())
                            && (clause.code() == null || required.code() == null
                                    || clause.code().equals(required.code()))) {
                        return true;
                    }
                }
                case DENY -> {
                    // Only denyAll implies denyAll, handled above.
                }
            }
        }
        return false;
    }

    /**
     * How {@code head} compares with {@code base}: {@link Comparison#WEAKER} means fewer callers are kept out.
     */
    public static Comparison compare(Set<Clause> base, Set<Clause> head) {
        boolean headCoversBase = base.stream().allMatch(clause -> implies(head, clause));
        boolean baseCoversHead = head.stream().allMatch(clause -> implies(base, clause));
        if (headCoversBase && baseCoversHead) {
            return Comparison.SAME;
        }
        if (headCoversBase) {
            return Comparison.STRONGER;
        }
        if (baseCoversHead) {
            return Comparison.WEAKER;
        }
        return Comparison.INCOMPARABLE;
    }

    /**
     * What {@code head} asks beyond {@code base}, when it asks at least everything {@code base} does: the clauses
     * {@code base} doesn't imply, as one line ({@code ""} when there are none). Empty when {@code head} drops part of
     * {@code base}, so it can't be shown as an addition.
     */
    public static Optional<String> added(Set<Clause> base, Set<Clause> head) {
        if (!base.stream().allMatch(clause -> implies(head, clause))) {
            return Optional.empty();
        }
        Set<Clause> extra = new LinkedHashSet<>();
        head.stream().filter(clause -> !implies(base, clause)).forEach(extra::add);
        return Optional.of(extra.isEmpty() ? "" : describe(extra));
    }

    /**
     * The simplified clauses as one line, e.g. {@code SCOPE_employees.read and ROLE_ADMIN}, or {@code none}.
     */
    public static String describe(Set<Clause> clauses) {
        List<Clause> simplified = simplify(clauses);
        return simplified.isEmpty() ? "none" : String.join(" and ", simplified.stream().map(Clause::toString)
                .toList());
    }

    /**
     * Drops clauses implied by others, for display: {@code [authenticated, ROLE_ADMIN]} becomes {@code [ROLE_ADMIN]}.
     */
    public static List<Clause> simplify(Set<Clause> clauses) {
        List<Clause> kept = new ArrayList<>();
        for (Clause clause : clauses) {
            Set<Clause> others = new LinkedHashSet<>(clauses);
            others.remove(clause);
            if (!implies(others, clause)) {
                kept.add(clause);
            }
        }
        return kept;
    }
}
