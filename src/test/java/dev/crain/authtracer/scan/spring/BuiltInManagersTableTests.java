package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.spring.BuiltInManagers.Arg;
import dev.crain.authtracer.scan.spring.BuiltInManagers.Decision;
import dev.crain.authtracer.scan.spring.BuiltInManagers.Manager;
import dev.crain.authtracer.scan.spring.BuiltInManagers.Managers;
import dev.crain.authtracer.scan.spring.BuiltInManagers.Text;
import dev.crain.authtracer.scan.spring.BuiltInManagers.Texts;
import org.junit.jupiter.api.Test;

/**
 * Decision 0063: the table of Spring's built-in managers, for the calls it reads only in part or not at all.
 */
class BuiltInManagersTableTests {

    private static final Requirement ADMIN = Requirement.anyAuthority(List.of("ROLE_ADMIN"));

    @Test
    void aFactoryWithArgumentsItDoesNotTakeIsNotRead() {
        assertThat(factory("AuthenticatedAuthorizationManager", "authenticated", new Text("x"))).isEmpty();
        assertThat(factory("AuthenticatedReactiveAuthorizationManager", "anonymous")).isEmpty();
        assertThat(factory("SingleResultAuthorizationManager", "abstain")).isEmpty();
        assertThat(factory("AuthorityAuthorizationManager", "hasRole", BuiltInManagers.UNKNOWN)).isEmpty();
        assertThat(factory("AuthorityAuthorizationManager", "withRoleHierarchy", new Text("x"))).isEmpty();
        assertThat(factory("AuthorizationManagers", "anyOf")).isEmpty();
        assertThat(factory("AuthorizationManagers", "not", new Text("x"))).isEmpty();
        assertThat(factory("AuthorizationManagers", "firstOf", new Manager(ADMIN))).isEmpty();
        assertThat(BuiltInManagers.factory(BuiltInManagers.PACKAGE + "sub.AuthorizationManagers", "anyOf", null,
                List.of(new Manager(ADMIN)))).isEmpty();
    }

    @Test
    void eachFactoryOfTheTable() {
        assertThat(factory("SingleResultAuthorizationManager", "permitAll").orElseThrow().kind())
                .isEqualTo(Kind.PERMIT_ALL);
        assertThat(factory("SingleResultAuthorizationManager", "denyAll").orElseThrow().kind())
                .isEqualTo(Kind.DENY_ALL);
        assertThat(factory("AuthenticatedAuthorizationManager", "rememberMe").orElseThrow().kind())
                .isEqualTo(Kind.REMEMBER_ME);
        assertThat(factory("AuthorityReactiveAuthorizationManager", "hasAnyAuthority", new Text("A"), new Text("B"))
                .orElseThrow().authorities()).containsExactly("A", "B");
        assertThat(factory("AllAuthoritiesAuthorizationManager", "hasAllRoles", new Text("A"), new Text("B"))
                .orElseThrow().kind()).isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(factory("AllAuthoritiesReactiveAuthorizationManager", "hasAllAuthorities", new Text("A"))
                .orElseThrow().authorities()).containsExactly("A");
        // hasAllPrefixedAuthorities(prefix, roles) with an unread second argument isn't read.
        assertThat(factory("AllAuthoritiesAuthorizationManager", "hasAllPrefixedAuthorities", new Text("P_"),
                BuiltInManagers.UNKNOWN)).isEmpty();
    }

    @Test
    void aSingleOperandIsThatOperandAndAnUnreadOneIsCustom() {
        assertThat(factory("AuthorizationManagers", "anyOf", new Manager(ADMIN))).contains(ADMIN);
        assertThat(factory("AuthorizationManagers", "allOf", new Manager(ADMIN))).contains(ADMIN);
        Requirement both = factory("AuthorizationManagers", "allOf", new Decision(false), new Manager(ADMIN),
                BuiltInManagers.UNKNOWN).orElseThrow();
        assertThat(both.kind()).isEqualTo(Kind.AND);
        assertThat(both.operands()).extracting(Requirement::kind).containsExactly(Kind.ANY_AUTHORITY, Kind.EXPRESSION);
        // A granting default with no custom operand changes nothing: built-in managers never abstain.
        assertThat(factory("AuthorizationManagers", "anyOf", new Decision(true), new Managers(List.of(ADMIN), true)))
                .contains(ADMIN);
    }

    @Test
    void namedRulesAndScopes() {
        assertThat(BuiltInManagers.named("permitAll", List.of(new Text("x")), BuiltInManagers.ROLE_PREFIX)).isEmpty();
        assertThat(BuiltInManagers.named("denyAll", List.of(new Text("x")), BuiltInManagers.ROLE_PREFIX)).isEmpty();
        assertThat(BuiltInManagers.named("denyAll", List.of(), BuiltInManagers.ROLE_PREFIX).orElseThrow().kind())
                .isEqualTo(Kind.DENY_ALL);
        assertThat(BuiltInManagers.named("access", List.of(new Text("x")), BuiltInManagers.ROLE_PREFIX)).isEmpty();
        assertThat(BuiltInManagers.scopes("hasAllScopes", List.of(new Text("a"), new Text("b")), "SCOPE_").kind())
                .isEqualTo(Kind.ALL_AUTHORITIES);
        assertThat(BuiltInManagers.scopes("hasScope", List.of(BuiltInManagers.UNKNOWN), "SCOPE_")).isNull();
        assertThat(BuiltInManagers.scopes("hasNoScope", List.of(new Text("a")), "SCOPE_")).isNull();
        assertThat(BuiltInManagers.texts(List.of())).isEmpty();
        assertThat(BuiltInManagers.texts(List.of(new Texts(List.of("a"), false)))).isEmpty();
    }

    private static Optional<Requirement> factory(String owner, String name, Arg... args) {
        return BuiltInManagers.factory(BuiltInManagers.PACKAGE + owner, name, null, List.of(args));
    }
}
