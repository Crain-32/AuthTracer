package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Spring Security 7.1.1's {@code UniqueSecurityAnnotationScanner} order, and JSR-250's annotations as one group.
 */
class AnnotationOrderFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("annotationorder");

    @Test
    void anOverriddenMethodKeepsTheAnnotationOfTheMethodItOverrides() {
        assertThat(checks("GET /purge")).containsExactly("@PreAuthorize ROLE_ADMIN");
    }

    @Test
    void aGenericInterfaceMethodsAnnotationAppliesToItsImplementation() {
        assertThat(checks("GET /delete")).containsExactly("@PreAuthorize ROLE_ADMIN");
    }

    @Test
    void anInterfaceMethodsAnnotationComesBeforeTheClasses() {
        assertThat(checks("GET /export")).containsExactly("@PreAuthorize ROLE_AUDITOR");
    }

    @Test
    void aSuperclassesClassLevelAnnotationApplies() {
        assertThat(checks("GET /rota")).containsExactly("@PreAuthorize ROLE_STAFF");
    }

    @Test
    void theClosestJsr250AnnotationIsTheOnlyOne() {
        assertThat(checks("GET /published")).containsExactly("@PermitAll PERMIT_ALL");
        assertThat(checks("GET /drafts")).containsExactly("@RolesAllowed ROLE_ADMIN");
        assertThat(checks("GET /vault")).containsExactly("@RolesAllowed ROLE_KEEPER");
    }

    private List<String> checks(String ingress) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .map(location -> location.mechanism() + " " + (location.requirement().authorities().isEmpty()
                        ? location.requirement().kind() : String.join(",", location.requirement().authorities())))
                .toList();
    }
}
