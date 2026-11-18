package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import org.junit.jupiter.api.Test;

class SpelRequirementsTests {

    private final SpelRequirements spel = new SpelRequirements("ROLE_");

    @Test
    void rolesGetThePrefixOnce() {
        Requirement requirement = spel.parse("hasAnyRole('ADMIN', 'ROLE_AUDITOR')");
        assertThat(requirement.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(requirement.authorities()).containsExactly("ROLE_ADMIN", "ROLE_AUDITOR");
        assertThat(requirement.expression()).isEqualTo("hasAnyRole('ADMIN', 'ROLE_AUDITOR')");
    }

    @Test
    void authoritiesAreKeptAsIs() {
        assertThat(spel.parse("hasAuthority('SCOPE_employees.read')").authorities())
                .containsExactly("SCOPE_employees.read");
    }

    @Test
    void booleanOperatorsBecomeATree() {
        Requirement requirement = spel.parse("hasRole('ADMIN') and isAuthenticated() or !hasRole('GUEST')");
        assertThat(requirement.kind()).isEqualTo(Kind.OR);
        assertThat(requirement.operands()).extracting(Requirement::kind).containsExactly(Kind.AND, Kind.NOT);
        assertThat(requirement.operands().get(0).operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.AUTHENTICATED);
    }

    @Test
    void aCheckComparedWithTrueOrFalseIsTheCheckOrItsNegation() {
        assertThat(spel.parse("hasRole('ADMIN') == true").kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(spel.parse("true == hasRole('ADMIN')").kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(spel.parse("hasRole('ADMIN') != false").kind()).isEqualTo(Kind.ANY_AUTHORITY);
        Requirement negated = spel.parse("hasRole('ADMIN') == false");
        assertThat(negated.kind()).isEqualTo(Kind.NOT);
        assertThat(negated.operands()).extracting(Requirement::kind).containsExactly(Kind.ANY_AUTHORITY);
        assertThat(spel.parse("hasRole('ADMIN') != true").kind()).isEqualTo(Kind.NOT);
        // Anything else compared stays as written.
        assertThat(spel.parse("hasRole('ADMIN') == isAnonymous()").kind()).isEqualTo(Kind.EXPRESSION);
    }

    @Test
    void ownershipChecksStayExpressions() {
        Requirement requirement = spel.parse("hasRole('ADMIN') or filterObject.owner == authentication.name");
        assertThat(requirement.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.EXPRESSION);
        assertThat(requirement.operands().get(1).expression()).contains("filterObject.owner");
    }

    @Test
    void theRootsPropertiesReadLikeItsMethods() {
        // @PreAuthorize("authenticated"), as in Spring Security's samples.
        assertThat(spel.parse("authenticated").kind()).isEqualTo(Kind.AUTHENTICATED);
        // Remember-me sessions are authenticated but not fully; isRememberMe() admits them only.
        assertThat(spel.parse("fullyAuthenticated").kind()).isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(spel.parse("isFullyAuthenticated()").kind()).isEqualTo(Kind.FULLY_AUTHENTICATED);
        assertThat(spel.parse("rememberMe").kind()).isEqualTo(Kind.REMEMBER_ME);
        assertThat(spel.parse("isRememberMe()").kind()).isEqualTo(Kind.REMEMBER_ME);
        assertThat(spel.parse("principal.enabled").kind()).isEqualTo(Kind.EXPRESSION);
    }

    @Test
    void permitAndDeny() {
        assertThat(spel.parse("permitAll").kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(spel.parse("permitAll()").kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(spel.parse("denyAll").kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(spel.parse("false").kind()).isEqualTo(Kind.DENY_ALL);
    }

    @Test
    void literalsAndTheRootsMethodsPermitOrDeny() {
        assertThat(spel.parse("true").kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(spel.parse("denyAll()").kind()).isEqualTo(Kind.DENY_ALL);
    }

    @Test
    void allOfSeveralRolesOrAuthorities() {
        Requirement roles = spel.parse("hasAllRoles('TELLER', 'AUDITOR')");
        assertThat(roles.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(roles.authorities()).containsExactly("ROLE_AUDITOR", "ROLE_TELLER");
        Requirement authorities = spel.parse("hasAllAuthorities('SCOPE_read', 'SCOPE_write')");
        assertThat(authorities.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(authorities.authorities()).containsExactly("SCOPE_read", "SCOPE_write");
    }

    @Test
    void anonymousAdmitsOnlyCallersWhoHaventSignedIn() {
        assertThat(spel.parse("isAnonymous()").kind()).isEqualTo(Kind.ANONYMOUS);
        assertThat(spel.parse("anonymous").kind()).isEqualTo(Kind.ANONYMOUS);
    }

    @Test
    void whatTheRootDoesntDecideStaysAnExpression() {
        // Another property or method of the root, a role from a parameter, and the checks given arguments they don't
        // take.
        for (String expression : new String[] {"isAnonymous('x')", "hasRole(#role)",
                "isAuthenticated('x')", "isFullyAuthenticated('x')", "isRememberMe('x')"}) {
            assertThat(spel.parse(expression).kind()).as(expression).isEqualTo(Kind.EXPRESSION);
        }
    }

    @Test
    void theFactorysPrefixReplacesTheHandlersDefault() {
        // GrantedAuthorityDefaults("") and no factory: roles are bare.
        assertThat(new SpelRequirements("").parse("hasRole('ADMIN')").authorities()).containsExactly("ADMIN");
        // The handler strips its ROLE_, the factory adds GRP_; a role already prefixed keeps it.
        SpelRequirements grouped = new SpelRequirements("GRP_", "ROLE_");
        assertThat(grouped.parse("hasAnyRole('ROLE_ADMIN', 'GRP_OPS', 'USER')").authorities())
                .containsExactly("GRP_ADMIN", "GRP_OPS", "GRP_USER");
    }

    @Test
    void withoutARoleHierarchyNothingIsWidened() {
        Requirement requirement = spel.parse("hasRole('HR')");
        assertThat(SpelRequirements.widened(requirement, null)).isSameAs(requirement);
    }

    @Test
    void unparseableExpressionsAreKeptVerbatim() {
        Requirement requirement = spel.parse("hasRole('ADMIN' ((");
        assertThat(requirement.kind()).isEqualTo(Kind.EXPRESSION);
        assertThat(requirement.expression()).isEqualTo("hasRole('ADMIN' ((");
    }
}
