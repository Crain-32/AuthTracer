package dev.crain.authtracer.scan.spring;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Credentials;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.ScanContext;

/**
 * Decision 0058: what a service calls on the infrastructure it is configured with, outside any request path, so the
 * linker links it to a scanned config server (decision 0055) or Eureka server (decision 0057). A config client
 * ({@code spring.config.import=configserver:<uri>}, or {@code spring.cloud.config.uri}) reads
 * {@code GET <uri>/{name}/{profiles}}, with {@code spring.cloud.config.username} its fixed credentials. A Eureka client
 * with a configured {@code eureka.client.service-url.defaultZone} registers ({@code POST <zone>/apps/{app}}), renews
 * ({@code PUT <zone>/apps/{app}/{id}}) and fetches the registry ({@code GET <zone>/apps/}), as its
 * {@code register-with-eureka} and {@code fetch-registry} allow.
 */
@Supports(Feature.INFRASTRUCTURE_CALLS)
final class InfrastructureCalls {

    private static final String CONFIG_CLIENT = "org.springframework.cloud.config.client.ConfigServerConfigDataLoader";
    private static final String EUREKA_CLIENT = "org.springframework.cloud.netflix.eureka.EurekaClientAutoConfiguration";

    private final ScanContext context;

    InfrastructureCalls(ScanContext context) {
        this.context = context;
    }

    List<Egress> detect() {
        List<Egress> calls = new ArrayList<>();
        if (context.findClass(CONFIG_CLIENT).isPresent()) {
            configServer().flatMap(uri -> call("Config client", "GET", uri, "/{name}/{profiles}",
                    CodeRef.ofClass(CONFIG_CLIENT)))
                    // Set, if only from the environment.
                    .map(found -> context.properties().getResolvingKnown("spring.cloud.config.username").isPresent()
                            ? found.withCredentials(Credentials.STATIC, "spring.cloud.config.username") : found)
                    .ifPresent(calls::add);
        }
        if (context.findClass(EUREKA_CLIENT).isPresent()
                && context.properties().flag("eureka.client.enabled").orElse(true)) {
            CodeRef site = CodeRef.ofClass(EUREKA_CLIENT);
            boolean register = context.properties().flag("eureka.client.register-with-eureka").orElse(true);
            boolean fetch = context.properties().flag("eureka.client.fetch-registry").orElse(true);
            for (String zone : context.properties().list("eureka.client.service-url.defaultZone")) {
                if (register) {
                    call("Eureka client", "POST", zone, "/apps/{app}", site).ifPresent(calls::add);
                    call("Eureka client", "PUT", zone, "/apps/{app}/{id}", site).ifPresent(calls::add);
                }
                if (fetch) {
                    call("Eureka client", "GET", zone, "/apps/", site).ifPresent(calls::add);
                }
            }
        }
        return calls;
    }

    /**
     * {@code spring.config.import}'s {@code [optional:]configserver:<uri>}, in a comma-separated or a YAML list (an
     * empty one reads {@code spring.cloud.config.uri}, by default {@code http://localhost:8888}).
     */
    private Optional<String> configServer() {
        for (String entry : context.properties().list("spring.config.import")) {
            String location = entry.startsWith("optional:") ? entry.substring("optional:".length()) : entry;
            if (location.startsWith("configserver:")) {
                String uri = location.substring("configserver:".length());
                return Optional.of(uri.isEmpty() ? context.properties().get("spring.cloud.config.uri")
                        .orElse("http://localhost:8888") : uri);
            }
        }
        return context.properties().get("spring.cloud.config.uri");
    }

    private static Optional<Egress> call(String client, String method, String url, String suffix, CodeRef site) {
        return AbsoluteUrl.parse(url).map(found -> found.call(client, method, found.path().replaceAll("/+$", "")
                + suffix, site));
    }
}
