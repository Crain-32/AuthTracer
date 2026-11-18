package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Where messages and gateway routes go when the configuration says: topics, queues and bindings from
 * {@code @Value}s and {@code @ConfigurationProperties}, route URIs a RouteLocator takes from properties, and Server
 * MVC routes made with the static {@code route(predicate, handler)}.
 */
class ConfiguredDestinationsFixtureTests {

    @Test
    void messagesGoToTheDestinationsTheConfigurationNames() {
        ApplicationGraph graph = FixtureScans.scan("messageconfig");
        assertThat(graph.nodes(Egress.class)).extracting(Egress::client, Egress::httpMethod, Egress::uriTemplate)
                .containsExactlyInAnyOrder(
                        // @Value fields and a constructor parameter's default.
                        tuple("KafkaTemplate", "KAFKA", "orders"), tuple("KafkaTemplate", "KAFKA", "shipments"),
                        // A @ConfigurationProperties record's component and its @DefaultValue.
                        tuple("KafkaTemplate", "KAFKA", "payments"), tuple("RabbitTemplate", "RABBIT", "audit"),
                        // One no file sets keeps its placeholder, which a listener of that name matches.
                        tuple("KafkaTemplate", "KAFKA", "${app.unset-topic}"),
                        tuple("JmsTemplate", "JMS", "invoices"),
                        // A StreamOperations field is the StreamBridge it is.
                        tuple("StreamBridge", "KAFKA", "events"));
        assertThat(graph.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG);
        assertThat(path(graph, "ingress:POST /events")).filteredOn(id -> id.startsWith("egress:")).hasSize(7);
    }

    @Test
    void routeLocatorUrisComeFromTheConfiguration() {
        ApplicationGraph graph = FixtureScans.scan("gatewayconfig");
        assertThat(graph.nodes(Egress.class)).extracting(Egress::uriTemplate, Egress::baseUrl)
                .containsExactlyInAnyOrder(
                        // A @Value field the route lambda reads.
                        tuple("/orders/**", "http://orders:8081"),
                        // A @Value parameter the lambda captures, through a load balancer.
                        tuple("/**", "http://billing"),
                        // A @ConfigurationProperties getter.
                        tuple("/stock/**", "http://stock:8082"),
                        // One no file sets: no service AuthTracer can name.
                        tuple("/unset/**", null));
    }

    @Test
    void staticServerMvcRoutesKeepTheirPredicatesPaths() {
        ApplicationGraph graph = FixtureScans.scan("gatewaymvcconfig");
        // The builder's route before them keeps its own path only.
        assertThat(graph.nodes(Egress.class)).extracting(Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl)
                .containsExactlyInAnyOrder(tuple("GET", "/catalog/**", null),
                        tuple("*", "/orders/**", "http://orders:8081"),
                        tuple("GET", "/stock/{sku}", "http://stock:8080"),
                        tuple("POST", "/payments", "http://payments:8080"));
        assertThat(graph.nodes(Ingress.class)).extracting(Ingress::id)
                .containsAll(List.of("ingress:GET /catalog/**", "ingress:* /orders/**", "ingress:GET /stock/{sku}",
                        "ingress:POST /payments"));
    }
}
