package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.ScanContext;

/**
 * Decision 0054: springdoc-openapi's endpoints (3.0, for Spring Boot 4), controllers in its jars that describe the
 * whole API: {@code GET <springdoc.api-docs.path>} (by default {@code /v3/api-docs}) and its {@code .yaml}, unless
 * {@code springdoc.api-docs.enabled=false}; with the UI, {@code <path>/swagger-config},
 * {@code <springdoc.swagger-ui.path>} ({@code /swagger-ui.html}) and the UI's resources under {@code /swagger-ui},
 * unless {@code springdoc.swagger-ui.enabled=false}. Only the request rules check them.
 */
@Supports(Feature.LIBRARY_ENDPOINTS)
final class ApiDocsEndpoints {

    private static final String API_DOCS = "org.springdoc.webmvc.api.OpenApiWebMvcResource";
    private static final String SWAGGER_UI = "org.springdoc.webmvc.ui.SwaggerWelcomeWebMvc";
    private static final String SWAGGER_CONFIG = "org.springdoc.webmvc.ui.SwaggerConfigResource";

    private final ScanContext context;

    ApiDocsEndpoints(ScanContext context) {
        this.context = context;
    }

    /**
     * @param reactive a WebFlux application, which springdoc's WebMVC starter doesn't serve
     */
    List<Ingress> library(boolean reactive) {
        List<Ingress> endpoints = new ArrayList<>();
        // springdoc's auto-configuration: Spring Boot, a Servlet web application.
        if (reactive || context.findClass(API_DOCS).isEmpty() || disabled("springdoc.api-docs.enabled")
                || !context.anyClassAnnotated(SpringNames.ENABLE_AUTO_CONFIGURATION)) {
            return endpoints;
        }
        String docs = context.properties().get("springdoc.api-docs.path").orElse("/v3/api-docs");
        CodeRef resource = CodeRef.ofClass(API_DOCS);
        endpoints.add(Ingress.of("GET", docs, resource));
        endpoints.add(Ingress.of("GET", docs + ".yaml", resource));
        if (context.findClass(SWAGGER_UI).isPresent() && !disabled("springdoc.swagger-ui.enabled")) {
            endpoints.add(Ingress.of("GET", docs + "/swagger-config", CodeRef.ofClass(SWAGGER_CONFIG)));
            CodeRef ui = CodeRef.ofClass(SWAGGER_UI);
            endpoints.add(Ingress.of("GET", context.properties().get("springdoc.swagger-ui.path")
                    .orElse("/swagger-ui.html"), ui));
            endpoints.add(Ingress.of("GET", "/swagger-ui/**", ui));
        }
        return endpoints;
    }

    private boolean disabled(String property) {
        return !context.properties().flag(property).orElse(true);
    }
}
