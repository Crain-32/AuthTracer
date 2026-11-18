package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.MethodNames;
import dev.crain.authtracer.scan.ScanContext;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0055: Spring Cloud Config Server's endpoints (5.0), controllers in its jar that serve every application's
 * configuration, secrets included, to whoever the request rules let in: with {@code @EnableConfigServer}, the
 * mappings of its {@code EnvironmentController} ({@code /{name}/{profiles}}, {@code /{name}-{profiles}.yml}, ...),
 * {@code ResourceController} and {@code EncryptionController} ({@code /encrypt}, {@code /decrypt}, {@code /key}),
 * read from their annotations under {@code spring.cloud.config.server.prefix}.
 */
@Supports(Feature.LIBRARY_ENDPOINTS)
final class ConfigServerEndpoints {

    private static final String ENABLE = "org.springframework.cloud.config.server.EnableConfigServer";
    static final String ENVIRONMENT = "org.springframework.cloud.config.server.environment.EnvironmentController";
    static final String RESOURCE = "org.springframework.cloud.config.server.resource.ResourceController";
    static final String ENCRYPTION = "org.springframework.cloud.config.server.encryption.EncryptionController";
    private static final List<String> CONTROLLERS = List.of(ENVIRONMENT, RESOURCE, ENCRYPTION);

    private final ScanContext context;

    ConfigServerEndpoints(ScanContext context) {
        this.context = context;
    }

    List<RequestMappings.Mapping> detect() {
        List<RequestMappings.Mapping> mappings = new ArrayList<>();
        if (!context.anyClassAnnotated(ENABLE)) {
            return mappings;
        }
        RequestMappings reader = new RequestMappings(context);
        for (String name : CONTROLLERS) {
            Optional<JavaSootClass> controller = context.findClass(name);
            if (controller.isEmpty()) {
                continue;
            }
            List<String> prefixes = reader.prefixes(controller.get()).stream().map(this::resolve).toList();
            for (JavaSootMethod method : controller.get().getMethods()) {
                Optional<RequestMappings.MappingInfo> info = reader.mappingInfo(method);
                if (info.isEmpty()) {
                    continue;
                }
                for (String route : RequestMappings.routes(prefixes, info.get().paths().stream().map(this::resolve)
                        .toList())) {
                    for (String httpMethod : info.get().methods()) {
                        mappings.add(new RequestMappings.Mapping(Ingress.of(httpMethod.equals("*") ? "GET"
                                : httpMethod, RequestMappings.withoutPatterns(route),
                                MethodNames.codeRef(method.getSignature())), method, true));
                    }
                }
            }
        }
        return mappings;
    }

    /**
     * {@code ${spring.cloud.config.server.prefix:}}, from the properties or its default; empty when unresolvable.
     */
    private String resolve(String text) {
        return context.properties().resolve(text).orElse("");
    }
}
