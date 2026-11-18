package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.diff.Exposures;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A controller's mappings on the interface it implements or on its superclass are its own, as Spring finds them.
 */
class InheritedMappingsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("inheritedmappings");

    @Test
    void mappingsOnTheInterfaceAreTheControllers() {
        assertThat(handler("ingress:GET /users/{id}")).isEqualTo("fixtures.inheritedmappings.UsersController");
        // A default method the controller doesn't override handles requests itself.
        assertThat(handler("ingress:POST /users")).isEqualTo("fixtures.inheritedmappings.UsersApi");
        assertThat(path(graph, "ingress:GET /users/{id}")).first().asString().endsWith(":/users/**");
    }

    @Test
    void handlersOfAnAbstractBaseControllerAreUnderTheSubclassesPath() {
        assertThat(handler("ingress:GET /orders")).isEqualTo("fixtures.inheritedmappings.CrudController");
        // Overridden without a mapping of its own, the method keeps the one it overrides.
        assertThat(handler("ingress:DELETE /orders/{id}")).isEqualTo("fixtures.inheritedmappings.OrdersController");
        assertThat(path(graph, "ingress:DELETE /orders/{id}"))
                .contains("location:METHOD:fixtures.inheritedmappings.OrdersController#delete(java.lang.String)"
                        + ":@PreAuthorize");
    }

    @Test
    void anOverrideOfAGenericHandlerIsTheHandlerNotItsBridge() {
        Ingress create = (Ingress) graph.node("ingress:POST /accounts").orElseThrow();
        assertThat(create.handler().method()).isEqualTo("create(fixtures.inheritedmappings.Account)");
        assertThat(path(graph, "ingress:POST /accounts")).contains("location:METHOD:"
                + "fixtures.inheritedmappings.AccountsController#create(fixtures.inheritedmappings.Account)"
                + ":@PreAuthorize");
        assertThat(graph.findings()).extracting(Finding::message)
                .noneMatch(message -> message.startsWith("On POST /accounts:"));
    }

    @Test
    void anInheritedHandlerCallsTheControllersOwnMethodsOnThis() {
        String guard = "location:METHOD:fixtures.inheritedmappings.Guard#admin(java.lang.String):@PreAuthorize";
        assertThat(path(graph, "ingress:GET /admin/docs/{id}")).contains(guard);
        assertThat(endpoint("GET /admin/docs/{id}")).isEqualTo("ROLE_ADMIN");
        assertThat(path(graph, "ingress:GET /public/docs/{id}")).doesNotContain(guard);
        assertThat(graph.findings()).extracting(Finding::message)
                .noneMatch(message -> message.startsWith("On GET /admin/docs/{id}:"));
    }

    private String endpoint(String endpoint) {
        return Exposures.of(graph).stream()
                .filter(exposure -> exposure.endpoint().equals(endpoint) && exposure.field().isEmpty())
                .map(Exposures.Exposure::requirement).findFirst().orElseThrow();
    }

    private String handler(String ingress) {
        return ((Ingress) graph.node(ingress).orElseThrow()).handler().className();
    }
}
