package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0052: JAX-RS resources on Jersey.
 */
class JaxRsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("jaxrs");

    @Test
    void registeredResourcesAreIngressUnderTheApplicationPath() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:GET /api/orders/{id}",
                "ingress:POST /api/orders", "ingress:GET /api/public/status")
                .noneMatch(id -> id.contains("hidden"));
        assertThat(((Ingress) graph.node("ingress:GET /api/orders/{id}").orElseThrow()).response().type())
                .isEqualTo("fixtures.jaxrs.Order");
        // Response names no body type.
        assertThat(((Ingress) graph.node("ingress:POST /api/orders").orElseThrow()).response()).isNull();
        // A resource's String is its body: no view of that name.
        assertThat(((Ingress) graph.node("ingress:GET /api/public/status").orElseThrow()).response().type())
                .isEqualTo("java.lang.String");
    }

    @Test
    void aResourceConfigBeanScanningAPackageAtTheBootApplicationPath() {
        ApplicationGraph packages = FixtureScans.scan("jaxrspackages");
        // Only the scanned package's resources, under spring.jersey.application-path.
        assertThat(packages.nodes(Ingress.class)).extracting(Ingress::id)
                .contains("ingress:GET /rest/catalog", "ingress:DELETE /rest/catalog/{id}")
                .noneMatch(id -> id.contains("debug"));
        // The method's @PermitAll before the class's @RolesAllowed.
        assertThat(jerseyCheck(packages, "ingress:GET /rest/catalog").requirement().kind())
                .isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(jerseyCheck(packages, "ingress:DELETE /rest/catalog/{id}").requirement().authorities())
                .containsExactly("ROLE_EDITOR");
    }

    private static AuthorizationLocation jerseyCheck(ApplicationGraph graph, String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(check -> check.mechanism().equals(JaxRsResources.MECHANISM)).findFirst().orElseThrow();
    }

    @Test
    void theFilterChainAndMethodSecurityApply() {
        assertThat(rule(graph, "GET /api/public/status").requirement().kind()).isEqualTo(Requirement.Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /api/orders/{id}").requirement().kind())
                .isEqualTo(Requirement.Kind.AUTHENTICATED);
        assertThat(path(graph, "ingress:POST /api/orders")).contains(
                "location:METHOD:fixtures.jaxrs.OrderResource#create(fixtures.jaxrs.Order):@PreAuthorize");
    }

    @Test
    void jerseyEnforcesRolesAllowedWithItsFeature() {
        assertThat(checks("ingress:GET /api/audit")).filteredOn(check -> check.mechanism().equals(
                "@RolesAllowed (Jersey)")).singleElement().satisfies(check -> assertThat(
                        check.requirement().authorities()).containsExactly("ROLE_AUDITOR"));
        // The method's @DenyAll overrides the class's @RolesAllowed.
        assertThat(checks("ingress:GET /api/audit/purge")).filteredOn(check -> check.mechanism().equals(
                "@RolesAllowed (Jersey)")).singleElement().satisfies(check -> assertThat(
                        check.requirement().kind()).isEqualTo(Requirement.Kind.DENY_ALL));
        assertThat(checks("ingress:GET /api/public/status")).noneMatch(check -> check.mechanism().contains("Jersey"));
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance)
                .map(AuthorizationLocation.class::cast).toList();
    }

    @Test
    void jerseysRolesAreAsWrittenWithThePrefixAndNoHierarchy() {
        ApplicationGraph roles = FixtureScans.scan("jaxrsroles");
        assertThat(roles.nodes(AuthorizationLocation.class)).filteredOn(check -> check.mechanism()
                .equals("@RolesAllowed (Jersey)")).singleElement().satisfies(check ->
                        assertThat(check.requirement().authorities()).containsExactly("user"));
    }
}
