package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Handlers told apart by {@code headers}, {@code consumes}, {@code produces} or {@code version} are separate Ingress.
 */
class MappingConditionsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("mappingconditions");

    @Test
    void handlersOfOnePathAreToldApartByTheirConditions() {
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id).contains(
                "ingress:GET /users?header:X-API-VERSION=1", "ingress:GET /users?header:X-API-VERSION=2",
                "ingress:POST /users?consumes:application/json", "ingress:POST /users?consumes:text/csv",
                "ingress:GET /users/me?version:1.0", "ingress:GET /users/me?version:2.0",
                // Alone on its path, a handler keeps its id.
                "ingress:GET /users/{id}");
        assertThat(((Ingress) graph.node("ingress:GET /users/me?version:2.0").orElseThrow()).response().type())
                .isEqualTo("fixtures.mappingconditions.UserV2");
    }

    @Test
    void eachVariantHasItsOwnChecks() {
        assertThat(methodChecks("ingress:GET /users?header:X-API-VERSION=2")).singleElement()
                .satisfies(check -> assertThat(check.requirement().authorities()).containsExactly("ROLE_ADMIN"));
        assertThat(methodChecks("ingress:GET /users?header:X-API-VERSION=1")).isEmpty();
        assertThat(methodChecks("ingress:POST /users?consumes:text/csv")).singleElement()
                .satisfies(check -> assertThat(check.requirement().authorities()).containsExactly("ROLE_IMPORTER"));
    }

    private java.util.List<AuthorizationLocation> methodChecks(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() == AuthorizationLocation.Scope.METHOD).toList();
    }
}
