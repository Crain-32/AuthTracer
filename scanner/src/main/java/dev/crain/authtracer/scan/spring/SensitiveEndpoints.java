package dev.crain.authtracer.scan.spring;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.GraphBuilder;
import dev.crain.authtracer.scan.ScanContext;
import sootup.java.core.JavaSootMethod;

/**
 * Decision 0061: endpoints libraries serve that hand out secrets or control of the application. One that answers
 * anyone is a finding of its own, not one more "No Authorization" among many. They are Actuator's write and delete
 * operations, its heap dump, and its {@code env} and {@code configprops} when they show values
 * ({@code show-values=always}); the H2 console when it lets in other hosts
 * ({@code spring.h2.console.settings.web-allow-others}, otherwise it refuses them itself); a config server's
 * configuration and its {@code /decrypt}; and a Eureka server's registrations. An endpoint answers anyone when no
 * check on its path asks for anything: none at all, or only {@code permitAll} ones ({@code ignoring()} included). A
 * check on some branches only doesn't count (decision 0027); a Provided requirement does.
 */
@Supports(Feature.FINDING_OPEN_SENSITIVE_ENDPOINT)
final class SensitiveEndpoints {

    /**
     * What writing to Spring Boot's and Spring Cloud's endpoints does; any other endpoint's writes change the running
     * application somehow.
     */
    private static final Map<String, String> WRITES = Map.of(
            "shutdown", "it stops the application",
            "loggers", "it changes log levels",
            "env", "it sets and resets the environment's properties, which a refresh then applies",
            "refresh", "it reloads the configuration and rebinds beans to it",
            "restart", "it restarts the application",
            "gateway", "it adds, changes and removes the gateway's routes",
            "caches", "it clears caches",
            "bindings", "it stops and starts message bindings");

    private record Sensitive(String what, String why) {
    }

    private final ScanContext context;
    private final ActuatorEndpoints actuator;
    private final Map<String, Sensitive> found = new LinkedHashMap<>();

    SensitiveEndpoints(ScanContext context, ActuatorEndpoints actuator) {
        this.context = context;
        this.actuator = actuator;
    }

    /**
     * Keeps the Ingress if it is a sensitive one.
     *
     * @param handler the method that handles it, or null for an endpoint a library servlet or filter serves
     */
    void note(Ingress ingress, JavaSootMethod handler) {
        sensitive(ingress, handler).ifPresent(sensitive -> found.put(ingress.id(), sensitive));
    }

    private Optional<Sensitive> sensitive(Ingress ingress, JavaSootMethod handler) {
        String owner = ingress.handler() == null ? "" : ingress.handler().className();
        if (owner.equals(ServletEndpoints.H2_SERVLET)) {
            return context.properties().flag("spring.h2.console.settings.web-allow-others").filter(allowed -> allowed)
                    .map(allowed -> new Sensitive("The H2 console", "it connects to whatever JDBC URL it is given and"
                            + " runs SQL there, and web-allow-others lets in other hosts"));
        }
        if (owner.equals(EurekaServerEndpoints.CONFIGURATION) && !ingress.httpMethod().equals("GET")) {
            return Optional.of(new Sensitive("The Eureka server's registry", "it registers, renews and cancels"
                    + " instances, so services that look others up there can be sent anywhere"));
        }
        if (handler == null) {
            return Optional.empty();
        }
        String declaring = handler.getDeclaringClassType().getFullyQualifiedName();
        if (declaring.equals(ConfigServerEndpoints.ENVIRONMENT) || declaring.equals(ConfigServerEndpoints.RESOURCE)) {
            return Optional.of(new Sensitive("The config server's configuration", "it serves every application's"
                    + " configuration, secrets included"));
        }
        if (declaring.equals(ConfigServerEndpoints.ENCRYPTION) && handler.getName().equals("decrypt")) {
            return Optional.of(new Sensitive("The config server's decrypt", "it decrypts whatever it is given"));
        }
        return actuator.endpointId(handler).flatMap(id -> actuator(id, ingress.httpMethod()));
    }

    private Optional<Sensitive> actuator(String id, String httpMethod) {
        String what = "Actuator's " + id + " endpoint";
        if (!httpMethod.equals("GET")) {
            return Optional.of(new Sensitive(what, WRITES.getOrDefault(id, "it changes the running application")));
        }
        if (id.equals("heapdump")) {
            return Optional.of(new Sensitive(what, "a heap dump holds whatever is in memory, credentials, tokens and"
                    + " sessions included"));
        }
        if ((id.equals("env") || id.equals("configprops")) && context.properties()
                .get("management.endpoint." + id + ".show-values").filter("always"::equalsIgnoreCase).isPresent()) {
            return Optional.of(new Sensitive(what, "it shows the configuration's values unmasked"
                    + " (show-values=always), secrets included"));
        }
        return Optional.empty();
    }

    /**
     * A finding for each sensitive endpoint no check on its path keeps anyone out of.
     */
    void report(GraphBuilder graph) {
        found.forEach((id, sensitive) -> {
            Ingress ingress = (Ingress) graph.find(id).orElseThrow();
            boolean checked = graph.path(id).stream().filter(edge -> !edge.conditional())
                    .map(edge -> graph.find(edge.to())).flatMap(Optional::stream)
                    .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                    .filter(location -> location.scope() != AuthorizationLocation.Scope.FIELD)
                    .anyMatch(location -> !location.requirement().permitsAnyone());
            if (!checked) {
                graph.finding(new Finding(Finding.Kind.OPEN_SENSITIVE_ENDPOINT, sensitive.what() + " ("
                        + ingress.endpoint() + ") answers anyone: " + sensitive.why() + ". Ask for a role for it in the"
                        + " filter chain, or declare a Provided requirement if something outside the application keeps"
                        + " callers out", ingress.handler()));
            }
        });
    }
}
