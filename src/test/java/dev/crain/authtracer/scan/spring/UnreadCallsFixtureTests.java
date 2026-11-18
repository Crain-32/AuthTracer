package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.CodeRef;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0082: a call AuthTracer recognises but can't read the target of is still on the graph.
 */
class UnreadCallsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("unreadcalls");

    @Test
    void aCallWhosePathIsNotReadIsAnEgressToAnUnknownPath() {
        assertThat(graph.nodes(Egress.class)).filteredOn(egress -> egress.callSite().className()
                .endsWith("OrderCalls")).extracting(egress -> egress.callSite().method(), Egress::client,
                        Egress::httpMethod, Egress::uriTemplate, Egress::baseUrl)
                .containsExactlyInAnyOrder(
                        // A whole URL may name its own host.
                        tuple("anywhere(java.lang.String)", "RestClient", "GET", "?", null),
                        // A path the client's builder adds is under its base URL; one that sets the host goes
                        // elsewhere.
                        tuple("pathFromParameter(java.lang.String)", "RestClient", "POST", "?", "http://orders:8080"),
                        tuple("otherHost(java.lang.String)", "RestClient", "GET", "/orders", null),
                        // The template's own function builds on the template.
                        tuple("templateFunction(java.lang.String)", "RestClient", "GET", "?", "http://orders:8080"),
                        tuple("templateFunctionWithConstants()", "RestClient", "GET", "/orders/{id}/lines",
                                "http://orders:8080"),
                        tuple("templateQuery()", "RestClient", "GET", "/orders", "http://orders:8080"),
                        // A replaced path, and a helper the builder is handed to, are read.
                        tuple("replaced()", "RestClient", "GET", "/v2/orders", "http://orders:8080"),
                        tuple("helped(long)", "RestClient", "GET", "/orders/{id}", "http://orders:8080"),
                        tuple("webAnywhere(java.net.URI)", "WebClient", "DELETE", "?", null),
                        tuple("templateAnywhere(java.lang.String)", "RestTemplate", "GET", "?", null),
                        tuple("templateExchange(java.lang.String)", "RestTemplate", "PUT", "?", null),
                        tuple("entity(org.springframework.http.RequestEntity)", "RestTemplate", "*", "?", null),
                        tuple("jdk(java.net.http.HttpClient,java.net.http.HttpRequest)", "HttpClient", "*", "?",
                                null),
                        // A builder from elsewhere may have set any method.
                        tuple("jdkBuilder(java.net.http.HttpClient,java.net.http.HttpRequest$Builder)", "HttpClient",
                                "*", "/orders", "http://orders:8080"),
                        tuple("jdkBuilder(java.net.http.HttpClient,java.net.http.HttpRequest$Builder)", "HttpClient",
                                "*", "?", null),
                        tuple("attribute(java.util.Map)", "RestTemplate", "GET", "?", null));
        assertThat(path(graph, "ingress:GET /orders")).filteredOn(id -> id.startsWith("egress:")).hasSize(12);
    }

    @Test
    void routesDocumentsRequestsAndDestinationsNotReadAreUnknownToo() {
        assertThat(graph.nodes(Egress.class)).filteredOn(egress -> !egress.callSite().className()
                .endsWith("OrderCalls")).extracting(Egress::client, Egress::httpMethod, Egress::uriTemplate,
                        Egress::baseUrl)
                .containsExactlyInAnyOrder(tuple("RSocketRequester", "RSOCKET", "?", "tcp://quotes:7001"),
                        tuple("GraphQlClient", "*", "?", "http://people:8095"),
                        tuple("WebServiceTemplate", "SOAP", "?", "http://countries:8080"),
                        tuple("WebServiceTemplate", "SOAP", "?", "http://countries:8080"),
                        // Two sends of one template in one method are one Egress.
                        tuple("KafkaTemplate", "KAFKA", "?", null),
                        tuple("JmsTemplate", "JMS", "?", null), tuple("RabbitTemplate", "RABBIT", "?", null),
                        tuple("StreamBridge", "KAFKA", "?", null));
    }

    @Test
    void eachSaysWhatItCouldNotRead() {
        List<String> messages = graph.findings().stream().filter(finding -> finding.kind()
                == Finding.Kind.OPAQUE_CONFIG).map(Finding::message).toList();
        assertThat(messages).hasSize(19);
        assertThat(messages).anySatisfy(message -> assertThat(message).contains(
                "The RestClient call in fixtures.unreadcalls.OrderCalls#pathFromParameter(java.lang.String) sends"
                        + " POST to http://orders:8080 with a path AuthTracer can't read (UriBuilder.path(..) with a"
                        + " value that isn't a constant)", "its Egress is POST ?, which links to nothing"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("RestTemplate",
                "a RequestEntity from a parameter"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("HttpClient",
                "a request from a parameter"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("HttpClient",
                "a request builder from a parameter"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("RestTemplate",
                "what Map.get(..) returns"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("WebServiceTemplate",
                "a message a callback writes"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("GraphQlClient",
                "a document from a parameter and a response path from a parameter"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("KafkaTemplate",
                "a topic AuthTracer can't read (a parameter)"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("JmsTemplate",
                "a Destination from a parameter"));
        assertThat(messages).anySatisfy(message -> assertThat(message).contains("RabbitTemplate",
                "an exchange from a parameter"));
    }

    @Test
    void theLinkerPlacesItNowhereAndSaysSo() {
        ApplicationGraph orders = new ApplicationGraph(ApplicationGraph.SCHEMA_VERSION, "orders", "test", 8080,
                AuthoritySource.UNKNOWN, List.of(Ingress.of("POST", "/{name}", CodeRef.ofMethod("orders.Orders",
                        "post(java.lang.String)"))), List.of(), List.of(), List.of(), List.of());
        SystemGraph system = new Linker().link(List.of(graph, orders), ZipkinTraces.of(List.of()));
        // Only the call whose path is known; a "?" would otherwise land on /{name}.
        assertThat(system.links()).extracting(Edge::from).containsExactly("unreadcalls/egress:fixtures.unreadcalls"
                + ".OrderCalls#jdkBuilder(java.net.http.HttpClient,java.net.http.HttpRequest$Builder) * /orders");
        // The calls whose service is known.
        assertThat(system.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH)
                .extracting(finding -> finding.location().method(), Finding::message).containsExactlyInAnyOrder(
                        tuple("pathFromParameter(java.lang.String)", "unreadcalls's RestClient POST call may go to"
                                + " orders, but AuthTracer can't read what it calls there: it links to none of their"
                                + " endpoints, so what it reaches, and the checks on the way, are not on"
                                + " unreadcalls's paths"),
                        tuple("templateFunction(java.lang.String)", "unreadcalls's RestClient GET call may go to"
                                + " orders, but AuthTracer can't read what it calls there: it links to none of their"
                                + " endpoints, so what it reaches, and the checks on the way, are not on"
                                + " unreadcalls's paths"));
    }
}
