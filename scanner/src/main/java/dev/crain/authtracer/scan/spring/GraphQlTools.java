package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.ScanContext;

/**
 * Decision 0060: what Spring Boot's GraphQL router (4.1.1 {@code GraphQlWebMvcAutoConfiguration}) serves besides the
 * operations: the GraphiQL UI, {@code GET <spring.graphql.graphiql.path>} ({@code /graphiql}) with
 * {@code spring.graphql.graphiql.enabled=true}, and the schema, {@code GET <spring.graphql.http.path>/schema}, with
 * {@code spring.graphql.schema.printer.enabled=true}. Only the request rules check them.
 */
@Supports(Feature.LIBRARY_ENDPOINTS)
final class GraphQlTools {

    private static final String GRAPHIQL = "org.springframework.graphql.server.webmvc.GraphiQlHandler";
    private static final String SCHEMA = "org.springframework.graphql.server.webmvc.SchemaHandler";

    private final ScanContext context;

    GraphQlTools(ScanContext context) {
        this.context = context;
    }

    /**
     * @param serves whether the application serves GraphQL operations
     */
    List<Ingress> library(boolean serves) {
        List<Ingress> endpoints = new ArrayList<>();
        if (!serves) {
            return endpoints;
        }
        if (enabled("spring.graphql.graphiql.enabled")) {
            endpoints.add(Ingress.of("GET", context.properties().get("spring.graphql.graphiql.path")
                    .orElse("/graphiql"), CodeRef.ofClass(GRAPHIQL)));
        }
        if (enabled("spring.graphql.schema.printer.enabled")) {
            endpoints.add(Ingress.of("GET", RequestMappings.join(context.properties().get("spring.graphql.http.path")
                    .orElse("/graphql"), "/schema"), CodeRef.ofClass(SCHEMA)));
        }
        return endpoints;
    }

    private boolean enabled(String property) {
        return context.properties().flag(property).orElse(false);
    }
}
