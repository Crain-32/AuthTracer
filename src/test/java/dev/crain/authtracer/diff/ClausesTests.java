package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import dev.crain.authtracer.diff.Clauses.Clause;
import dev.crain.authtracer.diff.Clauses.Comparison;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.spring.SpelRequirements;
import org.junit.jupiter.api.Test;

class ClausesTests {

    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"));
    private static final Requirement ADMIN_OR_AUDITOR = Requirement.anyAuthority(List.of("ROLE_ADMIN", "ROLE_AUDITOR"));
    private static final Requirement AUDITOR = Requirement.anyAuthority(List.of("ROLE_AUDITOR"));

    @Test
    void strengthOrder() {
        assertThat(compare(List.of(Requirement.authenticated()), List.of(Requirement.permitAll())))
                .isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(ADMIN), List.of(Requirement.authenticated()))).isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(ADMIN), List.of(Requirement.denyAll()))).isEqualTo(Comparison.STRONGER);
        assertThat(compare(List.of(), List.of(Requirement.authenticated()))).isEqualTo(Comparison.STRONGER);
    }

    @Test
    void moreAlternativesIsWeaker() {
        assertThat(compare(List.of(ADMIN), List.of(ADMIN_OR_AUDITOR))).isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(ADMIN_OR_AUDITOR), List.of(ADMIN))).isEqualTo(Comparison.STRONGER);
    }

    @Test
    void droppingAFactorIsWeaker() {
        // Decision 0037: an MFA factory's rule is the rule and all of its factors.
        Requirement both = Requirement.and(List.of(ADMIN, Requirement.allAuthorities(List.of("FACTOR_OTT",
                "FACTOR_PASSWORD"))));
        Requirement password = Requirement.and(List.of(ADMIN, Requirement.allAuthorities(List.of("FACTOR_PASSWORD"))));
        assertThat(compare(List.of(both), List.of(password))).isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(both), List.of(ADMIN))).isEqualTo(Comparison.WEAKER);
    }

    @Test
    void anOrWithTheOldRequirementAsABranchIsWeakerWhateverItAsks() {
        // A chain that may not be made leaves its rule or the next chain's: "X or authenticated", X unreadable.
        Requirement office = Requirement.expression("access(OfficeHours)");
        Requirement officeOrSignedIn = new Requirement(Requirement.Kind.OR, null, List.of(office,
                Requirement.authenticated()), null, null);
        assertThat(compare(List.of(office), List.of(officeOrSignedIn))).isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(officeOrSignedIn), List.of(office))).isEqualTo(Comparison.STRONGER);
        Requirement adminOrOffice = new Requirement(Requirement.Kind.OR, null, List.of(ADMIN, office), null, null);
        Requirement wider = new Requirement(Requirement.Kind.OR, null, List.of(adminOrOffice,
                Requirement.authenticated()), null, null);
        assertThat(compare(List.of(adminOrOffice), List.of(wider))).isEqualTo(Comparison.WEAKER);
        // Another branch, not the old requirement: can't be ranked.
        Requirement auditorOrOffice = new Requirement(Requirement.Kind.OR, null, List.of(AUDITOR, office), null,
                null);
        assertThat(compare(List.of(adminOrOffice), List.of(auditorOrOffice))).isEqualTo(Comparison.INCOMPARABLE);
    }

    @Test
    void sidewaysChangesAreIncomparable() {
        assertThat(compare(List.of(ADMIN), List.of(AUDITOR))).isEqualTo(Comparison.INCOMPARABLE);
    }

    @Test
    void moreChecksAreStronger() {
        assertThat(compare(List.of(Requirement.authenticated()), List.of(Requirement.authenticated(), ADMIN)))
                .isEqualTo(Comparison.STRONGER);
        assertThat(compare(List.of(Requirement.and(List.of(ADMIN, Requirement.authenticated()))), List.of(ADMIN)))
                .isEqualTo(Comparison.SAME);
    }

    @Test
    void expressionsCompareAsText() {
        Requirement owner = Requirement.expression("#id == authentication.name");
        assertThat(compare(List.of(owner), List.of(owner))).isEqualTo(Comparison.SAME);
        assertThat(compare(List.of(owner, ADMIN), List.of(ADMIN))).isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(owner), List.of(Requirement.expression("true == true"))))
                .isEqualTo(Comparison.INCOMPARABLE);
    }

    @Test
    void orOfAuthoritiesIsOneAnyClause() {
        Set<Clause> clauses = Clauses.of(List.of(Requirement.or(List.of(ADMIN, AUDITOR))));
        assertThat(clauses).singleElement().satisfies(clause ->
                assertThat(clause.authorities()).containsExactly("ROLE_ADMIN", "ROLE_AUDITOR"));
    }

    @Test
    void simplifyDropsImpliedClauses() {
        assertThat(Clauses.simplify(Clauses.of(List.of(Requirement.authenticated(), ADMIN_OR_AUDITOR, ADMIN))))
                .extracting(Clause::toString).containsExactly("ROLE_ADMIN");
    }

    private static Comparison compare(List<Requirement> base, List<Requirement> head) {
        return Clauses.compare(Clauses.of(base), Clauses.of(head));
    }

    @Test
    void anOrIsItsWeakestBranchWhenTheOthersImplyIt() {
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.or(List.of(ADMIN, Requirement.authenticated()))))))
                .isEqualTo("authenticated");
        assertThat(Clauses.of(List.of(Requirement.or(List.of(ADMIN, Requirement.permitAll()))))).isEmpty();
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.or(List.of(Requirement.denyAll(), ADMIN))))))
                .isEqualTo("ROLE_ADMIN");
        assertThat(Clauses.of(List.of(Requirement.or(List.of(ADMIN, Requirement.expression("#id == 1"))))))
                .singleElement().satisfies(clause -> assertThat(clause.kind()).isEqualTo(Clause.Kind.OPAQUE));
    }

    @Test
    void addedIsWhatTheHeadAsksBeyondTheBase() {
        Set<Clause> endpoint = Clauses.of(List.of(Requirement.authenticated()));
        assertThat(Clauses.added(endpoint, Clauses.of(List.of(Requirement.authenticated(), ADMIN)))).hasValue("ROLE_ADMIN");
        assertThat(Clauses.added(endpoint, endpoint)).hasValue("");
        assertThat(Clauses.added(Clauses.of(List.of(ADMIN)), Clauses.of(List.of(AUDITOR)))).isEmpty();
    }

    @Test
    void rememberMeSessionsRankBelowAFullSignIn() {
        Requirement fully = Requirement.fullyAuthenticated();
        // isFullyAuthenticated() to isAuthenticated(): remember-me sessions get in now.
        assertThat(compare(List.of(fully), List.of(Requirement.authenticated()))).isEqualTo(Comparison.WEAKER);
        // A role check says nothing about how the session signed in.
        assertThat(compare(List.of(fully), List.of(ADMIN))).isEqualTo(Comparison.INCOMPARABLE);
        assertThat(Clauses.describe(Clauses.of(List.of(fully, Requirement.authenticated()))))
                .isEqualTo("fullyAuthenticated");
    }

    /**
     * Decision 0105: {@code rememberMe()} and {@code isRememberMe()} let in remember-me sessions only (7.1.1
     * {@code AuthenticatedAuthorizationManager.RememberMeAuthorizationStrategy}: {@code isRememberMe}), so a caller who
     * signed in fully is kept out: they ask more than {@code authenticated}, and something else than
     * {@code fullyAuthenticated} or a role.
     */
    @Test
    void rememberMeLetsInRememberMeSessionsOnly() {
        Requirement rememberMe = Requirement.rememberMe();
        // rememberMe() to authenticated(): callers who signed in fully get in now.
        assertThat(compare(List.of(rememberMe), List.of(Requirement.authenticated()))).isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(Requirement.authenticated()), List.of(rememberMe)))
                .isEqualTo(Comparison.STRONGER);
        assertThat(compare(List.of(rememberMe), List.of(Requirement.permitAll()))).isEqualTo(Comparison.WEAKER);
        // No caller passes both: one signed in fully or through remember-me.
        assertThat(compare(List.of(Requirement.fullyAuthenticated()), List.of(rememberMe)))
                .isEqualTo(Comparison.INCOMPARABLE);
        assertThat(compare(List.of(rememberMe), List.of(ADMIN))).isEqualTo(Comparison.INCOMPARABLE);
        assertThat(compare(List.of(rememberMe), List.of(Requirement.and(List.of(rememberMe, ADMIN)))))
                .isEqualTo(Comparison.STRONGER);
        assertThat(Clauses.describe(Clauses.of(List.of(rememberMe, Requirement.authenticated()))))
                .isEqualTo("rememberMe");
    }

    @Test
    void aSignInOfTheSameKindIsTheSame() {
        Requirement fully = Requirement.fullyAuthenticated();
        Requirement rememberMe = Requirement.rememberMe();
        assertThat(compare(List.of(fully), List.of(Requirement.and(List.of(fully, ADMIN)))))
                .isEqualTo(Comparison.STRONGER);
        assertThat(compare(List.of(rememberMe), List.of(rememberMe))).isEqualTo(Comparison.SAME);
        // An expression says nothing about how the caller signed in.
        assertThat(compare(List.of(rememberMe), List.of(Requirement.expression("#id == 1"))))
                .isEqualTo(Comparison.INCOMPARABLE);
    }

    @Test
    void eachClauseReadsAsSpringSecurityWritesIt() {
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.rememberMe())))).isEqualTo("rememberMe");
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.denyAll())))).isEqualTo("denyAll");
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.permitAll())))).isEqualTo("none");
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.expression("#id == principal.id")))))
                .isEqualTo("expression #id == principal.id");
    }

    @Test
    void anOpaqueRequirementReadsAsItsNormalizedStructure() {
        assertThat(describe("!isRememberMe()")).isEqualTo("expression not rememberMe");
        assertThat(describe("!(isAuthenticated() and hasAllRoles('A', 'B'))"))
                .isEqualTo("expression not (authenticated and all of [ROLE_A, ROLE_B])");
        assertThat(describe("!(isFullyAuthenticated() or denyAll) and !permitAll"))
                .isEqualTo("expression not (fullyAuthenticated or denyAll) and expression not permitAll");
        assertThat(describe("!hasAllRoles('A') and !hasAnyRole('B', 'C')"))
                .isEqualTo("expression not ROLE_A and expression not any of [ROLE_B, ROLE_C]");
        // An or with a branch of several clauses is opaque too.
        assertThat(describe("hasRole('A') and hasRole('B') or hasRole('C')"))
                .isEqualTo("expression (ROLE_A and ROLE_B) or ROLE_C");
    }

    private static String describe(String expression) {
        return Clauses.describe(Clauses.of(List.of(SpelRequirements.standard(expression))));
    }

    @Test
    void aRoleAnonymousCallersHoldDoesNotKeepThemOut() {
        Requirement userOrAnonymous = Requirement.anyAuthority(List.of("ROLE_USER", "ROLE_ANONYMOUS"));
        assertThat(compare(List.of(Requirement.authenticated()), List.of(userOrAnonymous)))
                .isEqualTo(Comparison.INCOMPARABLE);
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.authenticated(), userOrAnonymous))))
                .isEqualTo("authenticated and any of [ROLE_ANONYMOUS, ROLE_USER]");
    }

    @Test
    void anonymousAsksNothingOfAnOutsider() {
        // Decision 0063: anyone can call without signing in, so moving a check to anonymous() weakens it.
        assertThat(compare(List.of(Requirement.authenticated()), List.of(Requirement.anonymous())))
                .isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(Requirement.anonymous()), List.of(Requirement.permitAll())))
                .isEqualTo(Comparison.SAME);
        assertThat(describe("isAnonymous() or hasRole('GUEST')")).isEqualTo("none");
        assertThat(describe("!isAnonymous()")).isEqualTo("expression not anonymous");
    }

    @Test
    void anonymousWithACheckNoAnonymousCallerPassesAdmitsNoOne() {
        // An MFA factory adds its factors to anonymous() (7.1.1): signed in, a caller isn't anonymous; not signed in,
        // it has no factors.
        Requirement factors = Requirement.allAuthorities(List.of("FACTOR_OTT", "FACTOR_PASSWORD"));
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.and(List.of(Requirement.anonymous(), factors))))))
                .isEqualTo("denyAll");
        // Across the checks of a path too, and for remembered callers, who aren't anonymous either.
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.anonymous(), ADMIN)))).isEqualTo("denyAll");
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.anonymous(), Requirement.rememberMe()))))
                .isEqualTo("denyAll");
        assertThat(describe("isAnonymous() and hasRole('USER')")).isEqualTo("denyAll");
        // An anonymous caller holds ROLE_ANONYMOUS; what an expression decides can't be told.
        Requirement anonymousRole = Requirement.anyAuthority(List.of("ROLE_ANONYMOUS"));
        assertThat(Clauses.describe(Clauses.of(List.of(Requirement.anonymous(), anonymousRole))))
                .isEqualTo("ROLE_ANONYMOUS");
        assertThat(describe("isAnonymous() and #id == 1")).startsWith("expression");
    }

    @Test
    void anOpaqueOrComparesItsOperandsAsTheScanWidenedThem() {
        Requirement owner = SpelRequirements.standard("hasRole('MANAGER') or #id == authentication.principal.id");
        // A RoleHierarchy added in the head lets interns through the role check; the source text is the same.
        Requirement widened = SpelRequirements.widened(owner, new TreeMap<>(Map.of("ROLE_INTERN",
                new TreeSet<>(Set.of("ROLE_MANAGER")))));
        assertThat(widened.expression()).isEqualTo(owner.expression());

        assertThat(compare(List.of(owner), List.of(owner))).isEqualTo(Comparison.SAME);
        // Each of its branches asks no more than the old one's: interns get in too, so it is weaker.
        assertThat(compare(List.of(owner), List.of(widened))).isEqualTo(Comparison.WEAKER);
        assertThat(compare(List.of(owner), List.of(SpelRequirements.standard(
                "hasAuthority('ROLE_MANAGER') or #id == authentication.principal.id")))).isEqualTo(Comparison.SAME);
    }
}
