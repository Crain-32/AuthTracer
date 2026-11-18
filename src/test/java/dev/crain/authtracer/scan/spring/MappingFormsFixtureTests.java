package dev.crain.authtracer.scan.spring;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Request mappings in the other forms controllers write them.
 */
class MappingFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("mappingforms");

    @Test
    void everyFormIsItsRoute() {
        // @RequestMapping's methods, the root path, and one handler at a path with and without its trailing slash
        // (two paths: Spring matches each literally); the base controller's abstract and static methods handle
        // nothing.
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .filteredOn(id -> !id.contains("/actuator/") && !id.contains("api-docs") && !id.contains("swagger-ui"))
                .containsExactlyInAnyOrder("ingress:GET /", "ingress:POST /legacy/orders",
                        "ingress:PUT /legacy/orders/{id}", "ingress:PATCH /legacy/orders/{id}",
                        "ingress:GET /api/orders", "ingress:POST /api/orders",
                        "ingress:POST /api/orders/{id}/cancel", "ingress:POST /api/invoices", "ingress:GET /health",
                        "ingress:GET /catalog", "ingress:GET /catalog/");
    }

    @Test
    void aComposedAnnotationsPathIsTheOneItsAliasSets() {
        // @GetJson("/api/orders"), whose value is @AliasFor(annotation = RequestMapping.class, attribute = "path").
        Ingress orders = (Ingress) graph.node("ingress:GET /api/orders").orElseThrow();
        assertThat(orders.handler().method()).isEqualTo("orders()");
        // @PostJson's elements alias the mapping's by their own names, as @PostMapping's do: path and value give the
        // path, name (an alias too) doesn't.
        assertThat(((Ingress) graph.node("ingress:POST /api/orders").orElseThrow()).handler().method())
                .isEqualTo("place()");
        assertThat(((Ingress) graph.node("ingress:POST /api/orders/{id}/cancel").orElseThrow()).handler().method())
                .isEqualTo("cancel(long)");
        // @Create's value aliases @RequestMapping's, its reason @ResponseStatus's; @HealthCheck has its meta's path.
        assertThat(((Ingress) graph.node("ingress:POST /api/invoices").orElseThrow()).handler().method())
                .isEqualTo("invoice()");
        assertThat(((Ingress) graph.node("ingress:GET /health").orElseThrow()).handler().method())
                .isEqualTo("health()");
    }
}
