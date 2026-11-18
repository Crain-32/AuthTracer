package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.ScanContext;

/**
 * Decision 0057: a Eureka server's endpoints (Spring Cloud Netflix 5.0), with {@code @EnableEurekaServer}: its REST
 * API under {@code /eureka/*} (Jersey resources, fixed in {@code EurekaServerAutoConfiguration}), where instances
 * register ({@code POST}), renew ({@code PUT}), cancel ({@code DELETE}) and anyone it lets in reads the registry
 * ({@code GET}); and its dashboard at {@code eureka.dashboard.path} ({@code /}, and {@code /lastn}) unless
 * {@code eureka.dashboard.enabled=false}. Only the request rules check them.
 */
@Supports(Feature.LIBRARY_ENDPOINTS)
final class EurekaServerEndpoints {

    private static final String ENABLE = "org.springframework.cloud.netflix.eureka.server.EnableEurekaServer";
    static final String CONFIGURATION =
            "org.springframework.cloud.netflix.eureka.server.EurekaServerAutoConfiguration";
    private static final String DASHBOARD = "org.springframework.cloud.netflix.eureka.server.EurekaController";

    private final ScanContext context;

    EurekaServerEndpoints(ScanContext context) {
        this.context = context;
    }

    List<Ingress> library() {
        List<Ingress> endpoints = new ArrayList<>();
        if (context.findClass(CONFIGURATION).isEmpty()
                || !context.anyClassAnnotated(ENABLE)) {
            return endpoints;
        }
        CodeRef api = CodeRef.ofClass(CONFIGURATION);
        for (String method : List.of("GET", "POST", "PUT", "DELETE")) {
            endpoints.add(Ingress.of(method, "/eureka/**", api));
        }
        if (context.properties().flag("eureka.dashboard.enabled").orElse(true)) {
            String path = context.properties().get("eureka.dashboard.path").orElse("/");
            CodeRef dashboard = CodeRef.ofClass(DASHBOARD);
            endpoints.add(Ingress.of("GET", path, dashboard));
            endpoints.add(Ingress.of("GET", RequestMappings.join(path, "/lastn"), dashboard));
        }
        return endpoints;
    }
}
