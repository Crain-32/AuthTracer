package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0063: Spring Security's built-in managers, read from one table wherever they are given.
 */
class BuiltInManagersFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("builtinmanagers");

    @Test
    void anExplicitArrayAfterAStringIsTheRolePrefixOverload() {
        Requirement prefixed = rule(graph, "GET /prefixed/run").requirement();
        assertThat(prefixed.kind()).isEqualTo(Kind.ANY_AUTHORITY);
        assertThat(prefixed.authorities()).containsExactly("GROUP_OPS", "GROUP_SRE");
    }

    @Test
    void allOfSeveralRolesOrPrefixedAuthorities() {
        Requirement roles = rule(graph, "GET /all-roles/run").requirement();
        assertThat(roles.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(roles.authorities()).containsExactly("ROLE_AUDITOR", "ROLE_TELLER");
        assertThat(rule(graph, "GET /all-prefixed/run").requirement().authorities())
                .containsExactly("GROUP_OPS", "GROUP_SRE");
        Requirement scopes = rule(graph, "GET /scoped/run").requirement();
        assertThat(scopes.kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(scopes.authorities()).containsExactly("SCOPE_read", "SCOPE_write");
    }

    @Test
    void composedManagersAreTheirOperands() {
        Requirement either = rule(graph, "GET /either/run").requirement();
        assertThat(either.kind()).isEqualTo(Kind.OR);
        assertThat(either.operands()).extracting(Requirement::authorities)
                .containsExactly(sorted("ROLE_ADMIN"), sorted("SCOPE_reports"));
        Requirement both = rule(graph, "GET /both/run").requirement();
        assertThat(both.kind()).isEqualTo(Kind.AND);
        assertThat(both.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.FULLY_AUTHENTICATED);
        assertThat(rule(graph, "GET /members/run").requirement())
                .isEqualTo(Requirement.not(Requirement.anonymous()));
        assertThat(rule(graph, "GET /open/run").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
    }

    @Test
    void aGrantingDefaultDecisionAdmitsAnyoneWhenAManagerAbstains() {
        // anyOf(new AuthorizationDecision(true), hasRole("ADMIN"), new Abstaining()): the custom one abstains, which
        // its body shows (decision 0065).
        Requirement abstaining = rule(graph, "GET /abstaining/run").requirement();
        assertThat(abstaining.kind()).isEqualTo(Kind.OR);
        assertThat(abstaining.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.PERMIT_ALL);
        assertThat(abstaining.permitsAnyone()).isTrue();
        // One AuthTracer can't read may abstain too.
        Requirement unread = BuiltInManagers.factory(BuiltInManagers.PACKAGE + "AuthorizationManagers", "anyOf", null,
                List.of(new BuiltInManagers.Decision(true), new BuiltInManagers.Managers(List.of(
                        Requirement.anyAuthority(List.of("ROLE_ADMIN"))), false))).orElseThrow();
        assertThat(unread.operands()).extracting(Requirement::kind)
                .containsExactly(Kind.ANY_AUTHORITY, Kind.EXPRESSION, Kind.PERMIT_ALL);
    }

    @Test
    void anonymousIsItsOwnRequirementInTheDslAndInSpel() {
        assertThat(rule(graph, "GET /guests/run").requirement().kind()).isEqualTo(Kind.ANONYMOUS);
        assertThat(methodCheck("GET /guests/run").requirement().kind()).isEqualTo(Kind.ANONYMOUS);
        Requirement open = methodCheck("GET /open/run").requirement();
        assertThat(open.kind()).isEqualTo(Kind.OR);
        assertThat(open.operands().getFirst().kind()).isEqualTo(Kind.ANONYMOUS);
    }

    @Test
    void aRoleThatIsntAConstantIsUnreadNotDropped() {
        // hasAnyRole("LEAD", role): reading LEAD alone would ask for more than the rule does.
        assertThat(rule(graph, "GET /team/run").requirement().withCode(null))
                .isEqualTo(Requirement.expression("hasAnyRole(?)"));
    }

    @Test
    void onlyAManagerGivenTheRoleHierarchyIsWidenedByIt() {
        assertThat(rule(graph, "GET /hierarchical/run").requirement().authorities())
                .containsExactly("ROLE_ADMIN", "ROLE_OPS");
        assertThat(rule(graph, "GET /flat/run").requirement().authorities()).containsExactly("ROLE_OPS");
    }

    @Test
    void theTableTellsOverloadsApartByTheirParameterTypes() {
        BuiltInManagers.Arg prefix = new BuiltInManagers.Text("GROUP_");
        BuiltInManagers.Arg roles = new BuiltInManagers.Texts(List.of("OPS"), true);
        assertThat(BuiltInManagers.factory(BuiltInManagers.PACKAGE + "AuthorityAuthorizationManager", "hasAnyRole",
                List.of("java.lang.String", "java.lang.String[]"), List.of(prefix, roles)).orElseThrow()
                .authorities()).containsExactly("GROUP_OPS");
        // A Groovy call has no signature: a string then an array is the prefix overload too.
        assertThat(BuiltInManagers.factory(BuiltInManagers.PACKAGE + "AuthorityAuthorizationManager", "hasAnyRole",
                null, List.of(prefix, roles)).orElseThrow().authorities()).containsExactly("GROUP_OPS");
        assertThat(BuiltInManagers.factory(BuiltInManagers.PACKAGE + "AuthorityAuthorizationManager", "hasAnyRole",
                List.of("java.lang.String[]"), List.of(roles)).orElseThrow().authorities())
                .containsExactly("ROLE_OPS");
        assertThat(BuiltInManagers.factory(BuiltInManagers.PACKAGE + "AuthenticatedReactiveAuthorizationManager",
                "authenticated", List.of(), List.of())).contains(Requirement.authenticated());
        assertThat(BuiltInManagers.factory(BuiltInManagers.PACKAGE + "AuthorizationManagers", "not", null,
                List.of(BuiltInManagers.UNKNOWN))).isEmpty();
        assertThat(BuiltInManagers.factory("com.example.Managers", "hasRole", null,
                List.of(new BuiltInManagers.Text("X")))).isEmpty();
    }

    private AuthorizationLocation methodCheck(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() == AuthorizationLocation.Scope.METHOD).findFirst().orElseThrow();
    }

    private static java.util.SortedSet<String> sorted(String... authorities) {
        return new java.util.TreeSet<>(List.of(authorities));
    }
}
