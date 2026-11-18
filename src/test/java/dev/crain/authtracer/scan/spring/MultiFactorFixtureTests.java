package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0037: multi-factor authentication.
 */
class MultiFactorFixtureTests {

    private static final Requirement BOTH = Requirement.allAuthorities(List.of("FACTOR_OTT", "FACTOR_PASSWORD"));

    @Test
    void enableMultiFactorAuthenticationAddsTheFactorsToEveryRule() {
        ApplicationGraph graph = FixtureScans.scan("mfa");
        Requirement admin = check(graph, "GET /admin/users", "authorizeHttpRequests").requirement();
        assertThat(admin.kind()).isEqualTo(Requirement.Kind.AND);
        assertThat(admin.operands()).extracting(Requirement::kind, Requirement::authorities).containsExactly(
                org.assertj.core.groups.Tuple.tuple(Requirement.Kind.ANY_AUTHORITY, sorted("ROLE_ADMIN")),
                org.assertj.core.groups.Tuple.tuple(Requirement.Kind.ALL_AUTHORITIES, BOTH.authorities()));
        assertThat(admin.expression()).isEqualTo("hasRole(ADMIN) with factors FACTOR_OTT, FACTOR_PASSWORD");
        // permitAll needs no factors; anonymous does, which no anonymous caller has.
        assertThat(check(graph, "GET /public", "authorizeHttpRequests").requirement().kind())
                .isEqualTo(Requirement.Kind.PERMIT_ALL);
        Requirement signup = check(graph, "GET /signup", "authorizeHttpRequests").requirement();
        assertThat(signup.kind()).isEqualTo(Requirement.Kind.AND);
        assertThat(signup.operands()).extracting(Requirement::authorities).contains(BOTH.authorities());
        // So the sign-up page admits no one: what a caller needs to reach it is denyAll.
        assertThat(Exposures.of(graph)).filteredOn(exposure -> exposure.endpoint().equals("GET /signup")
                && exposure.field().isEmpty()).extracting(Exposures.Exposure::requirement).containsExactly("denyAll");
        // Pre/post too; and the factory replaces the RoleHierarchy bean, so ROLE_ADMIN doesn't imply ROLE_USER.
        Requirement report = check(graph, "GET /report", "@PreAuthorize").requirement();
        assertThat(report.operands()).extracting(Requirement::authorities)
                .containsExactly(sorted("ROLE_USER"), BOTH.authorities());
    }

    @Test
    void aFactoryBuiltInPlaceAndAFactorsManager() {
        ApplicationGraph graph = FixtureScans.scan("mfalocal");
        Requirement admin = check(graph, "GET /admin/users", "authorizeHttpRequests").requirement();
        assertThat(admin.operands()).extracting(Requirement::authorities)
                .containsExactly(sorted("ROLE_ADMIN"), BOTH.authorities());
        Requirement settings = check(graph, "GET /settings/password", "authorizeHttpRequests").requirement();
        assertThat(settings.kind()).isEqualTo(Requirement.Kind.ALL_AUTHORITIES);
        assertThat(settings.authorities()).containsExactly("FACTOR_PASSWORD");
        assertThat(settings.expression()).isEqualTo("factors FACTOR_PASSWORD (recent)");
        // An AuthorizationManager bean the chain is handed.
        Requirement profile = check(graph, "GET /profile", "authorizeHttpRequests").requirement();
        assertThat(profile.operands()).extracting(Requirement::kind)
                .containsExactly(Requirement.Kind.AUTHENTICATED, Requirement.Kind.ALL_AUTHORITIES);
        assertThat(profile.expression()).isEqualTo("authenticated with factors FACTOR_OTT, FACTOR_PASSWORD (recent)");
        // Other rules don't go through the local factory.
        assertThat(check(graph, "GET /home", "authorizeHttpRequests").requirement().kind())
                .isEqualTo(Requirement.Kind.AUTHENTICATED);
    }

    @Test
    void requiredAuthoritiesForNamedUsersOnly() {
        ApplicationGraph graph = FixtureScans.scan("mfaperuser");
        Requirement home = check(graph, "GET /home", "authorizeHttpRequests").requirement();
        assertThat(home.kind()).isEqualTo(Requirement.Kind.AND);
        Requirement perUser = home.operands().getLast();
        assertThat(perUser.kind()).isEqualTo(Requirement.Kind.OR);
        assertThat(perUser.operands()).extracting(Requirement::kind)
                .containsExactly(Requirement.Kind.ALL_AUTHORITIES, Requirement.Kind.PERMIT_ALL);
        assertThat(perUser.expression()).isEqualTo("factors FACTOR_OTT when the user is admin");
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
    }

    @Test
    void factorsOnlyWhenAPasskeyIsRegistered() {
        ApplicationGraph graph = FixtureScans.scan("mfawhen");
        Requirement home = check(graph, "GET /home", "authorizeHttpRequests").requirement();
        assertThat(home.operands().getLast().expression())
                .isEqualTo("factors FACTOR_PASSWORD, FACTOR_WEBAUTHN when WebAuthn is registered");
        assertThat(home.operands().getLast().operands().getLast().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
    }

    private static java.util.SortedSet<String> sorted(String... authorities) {
        return new java.util.TreeSet<>(List.of(authorities));
    }

    private static AuthorizationLocation check(ApplicationGraph graph, String ingress, String mechanism) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals(mechanism)).findFirst().orElseThrow();
    }
}
