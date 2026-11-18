package dev.crain.authtracer.mutation;

import java.util.Comparator;
import java.util.List;

/**
 * One change to one source file of a fixture, of the kind a pull request makes that may weaken authorization: a
 * method-security annotation dropped, a request rule loosened, a matcher widened.
 *
 * @param operator what kind of change ({@link Operator})
 * @param file the source file, relative to the fixture's package directory
 * @param line the line the change starts on
 * @param description the change, e.g. {@code drop @Secured("ROLE_ADMIN") on admin()}
 * @param edits replacements of the file's text, none overlapping
 */
record Mutation(Operator operator, String file, int line, String description, List<Edit> edits) {

    /**
     * The kinds of change, each one a real pull request makes.
     */
    enum Operator {
        /** A method-security annotation ({@code @PreAuthorize}, {@code @Secured}, ...) dropped. */
        DROP_METHOD_CHECK,
        /**
         * A method check loosened: an expression to {@code isAuthenticated()}, {@code @DenyAll} to {@code @PermitAll}.
         */
        LOOSEN_METHOD_CHECK,
        /**
         * One more role let in: {@code hasRole('A')} to {@code hasAnyRole('A','USER')}, an extra {@code @Secured} role.
         */
        WIDEN_ROLES,
        /** An expression's {@code and} turned into {@code or}. */
        AND_TO_OR,
        /** Method security turned off: {@code @EnableMethodSecurity} dropped, or one of its kinds of annotation off. */
        DISABLE_METHOD_SECURITY,
        /**
         * A security configuration class's {@code @Configuration} dropped, as an upgrade to Spring Security 6 leaves it
         * when the {@code @Enable} annotation carried it: what it enables and the chains it makes are gone.
         */
        DROP_CONFIGURATION,
        /** A request rule's authorization turned into {@code permitAll()}. */
        LOOSEN_RULE,
        /** A request rule's authorization turned into {@code authenticated()}. */
        RULE_TO_AUTHENTICATED,
        /** A request rule dropped: what it matched falls to the rules after it. */
        DROP_RULE,
        /** A {@code permitAll()} rule for a protected rule's paths (or every path) put before every rule. */
        EARLY_PERMIT_ALL,
        /** Two adjacent request rules swapped. */
        REORDER_RULES,
        /** Two security filter chains next to each other in order swap their {@code @Order}. */
        REORDER_CHAINS,
        /** A protected rule's or a chain's matcher matching less: {@code /admin/**} to {@code /admin}, GET only. */
        NARROW_MATCHER,
        /** A {@code permitAll()} rule's (or {@code ignoring()}'s) matcher matching more: its parent path. */
        WIDEN_MATCHER,
        /** A role hierarchy turned upside down. */
        INVERT_ROLE_HIERARCHY,
        /**
         * Code that decides grants everyone: a custom {@code AuthorizationManager}'s or {@code PermissionEvaluator}'s
         * decision, or a method an expression calls on a bean ({@code @authz.canRead(..)}), returns yes.
         */
        GRANT_IN_CODE
    }

    /**
     * Replaces {@code [start, end)} of the file's text.
     */
    record Edit(int start, int end, String replacement) {
    }

    String apply(String source) {
        StringBuilder text = new StringBuilder(source);
        edits.stream().sorted(Comparator.comparingInt(Edit::start).reversed())
                .forEach(edit -> text.replace(edit.start(), edit.end(), edit.replacement()));
        return text.toString();
    }
}
