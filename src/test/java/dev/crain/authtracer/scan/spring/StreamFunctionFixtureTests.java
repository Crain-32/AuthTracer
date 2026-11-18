package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.groups.Tuple.tuple;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0047: Spring Cloud Stream's functional bindings.
 */
class StreamFunctionFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("stream");

    @Test
    void boundFunctionsReceiveFromTheirDestinations() {
        // Two consumers of orders, told apart by the function; the supplier is polled; unbound isn't in the definition.
        assertThat(graph.nodes(Ingress.class)).filteredOn(NoCaller::applies).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:KAFKA orders?handler=StreamApp.shipOrders",
                        "ingress:KAFKA orders?handler=StreamApp.invoice", "ingress:SCHEDULED StreamApp.heartbeat");
    }

    @Test
    void aConsumersChecksRunWithoutACaller() {
        assertThat(nodes("ingress:KAFKA orders?handler=StreamApp.shipOrders"))
                .filteredOn(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .singleElement().satisfies(check -> {
                    assertThat(check.mechanism()).isEqualTo("@PreAuthorize (no caller)");
                    assertThat(check.requirement().kind()).isEqualTo(Requirement.Kind.DENY_ALL);
                });
    }

    @Test
    void resultsAndSendsGoToTheirBindingsDestinations() {
        assertThat(nodes("ingress:KAFKA orders?handler=StreamApp.invoice")).filteredOn(Egress.class::isInstance)
                .map(Egress.class::cast).extracting(Egress::httpMethod, Egress::uriTemplate)
                .containsExactly(tuple("KAFKA", "invoices"));
        assertThat(nodes("ingress:SCHEDULED StreamApp.heartbeat")).filteredOn(Egress.class::isInstance)
                .map(Egress.class::cast).extracting(Egress::uriTemplate).containsExactly("heartbeat-out-0");
        // A configured binding's destination, or a destination by name.
        assertThat(nodes("ingress:POST /orders")).filteredOn(Egress.class::isInstance).map(Egress.class::cast)
                .extracting(Egress::client, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("StreamBridge", "orders"), tuple("StreamBridge", "audit"));
    }

    @Test
    void streamProducersLinkToKafkaListeners() {
        ApplicationGraph producer = FixtureScans.scan("messagingproducer");
        SystemGraph system = new Linker().link(List.of(producer, graph), ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).contains(
                "stream/ingress:KAFKA orders?handler=StreamApp.shipOrders",
                "stream/ingress:KAFKA orders?handler=StreamApp.invoice");
    }

    @Test
    void componentFunctionsAreNamedAsTheirBeans() {
        ApplicationGraph components = FixtureScans.scan("streamcomponents");
        assertThat(components.nodes(Ingress.class)).filteredOn(NoCaller::applies)
                .extracting(Ingress::id, ingress -> ingress.handler().className()).containsExactlyInAnyOrder(
                        tuple("ingress:KAFKA orders", "fixtures.streamcomponents.Enrich"),
                        tuple("ingress:KAFKA enriched", "fixtures.streamcomponents.AuditConsumer"),
                        tuple("ingress:KAFKA archived", "fixtures.streamcomponents.ArchiveConsumer"));
        assertThat(path(components, "ingress:KAFKA enriched")).anySatisfy(id -> assertThat(id).endsWith(
                "Ledger#record(fixtures.streamcomponents.Order):@PreAuthorize:no-caller"));
        assertThat(path(components, "ingress:KAFKA orders")).map(id -> components.node(id).orElseThrow())
                .filteredOn(Egress.class::isInstance).map(Egress.class::cast).extracting(Egress::uriTemplate)
                .containsExactly("enriched");
    }

    @Test
    void eachBindingHasItsBinder() {
        ApplicationGraph forms = FixtureScans.scan("streamforms");
        // RabbitMQ by default, Kafka for enrich's input; audit is its @Bean's name, ticker a supplier component.
        // inventory's binder isn't one AuthTracer knows, and the application has no reconcile.
        assertThat(forms.nodes(Ingress.class)).filteredOn(NoCaller::applies).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:RABBIT audits", "ingress:KAFKA raw",
                        "ingress:SCHEDULED Ticker.get");
        assertThat(forms.nodes(Egress.class)).extracting(Egress::httpMethod, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("RABBIT", "enriched"), tuple("RABBIT", "ticker-out-0"));
    }

    @Test
    void aDefaultBinderAuthTracerDoesntKnowBindsNothingItCanLink() {
        assertThat(FixtureScans.scan("streamotherbinder").nodes(Ingress.class)).noneMatch(NoCaller::applies);
    }

    @Test
    void withoutABinderOnTheClasspathNothingIsBound() {
        ApplicationGraph unbound = FixtureScans.scanWithout("stream", "spring-cloud-stream-binder-kafka");
        assertThat(unbound.nodes(Ingress.class)).noneMatch(NoCaller::applies);
        assertThat(unbound.nodes(Egress.class)).isEmpty();
        // Nor without Spring Cloud Stream itself, its binders with it.
        assertThat(FixtureScans.scanWithout("streamcomponents", "spring-cloud-stream").nodes(Ingress.class))
                .noneMatch(NoCaller::applies);
    }

    @Test
    void kotlinFunctionTypesThatAreSuppliersAndFunctions() {
        ApplicationGraph kotlin = FixtureScans.scan("streamkotlinforms");
        assertThat(kotlin.nodes(Ingress.class)).filteredOn(NoCaller::applies).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:SCHEDULED StreamKotlinFormsApp.heartbeat", "ingress:KAFKA orders");
        // (Order) -> Quote returns what it sends on: price-out-0's destination.
        assertThat(path(kotlin, "ingress:KAFKA orders")).map(id -> kotlin.node(id).orElseThrow())
                .filteredOn(Egress.class::isInstance).map(Egress.class::cast).extracting(Egress::uriTemplate)
                .containsExactly("quotes");
    }

    @Test
    void aKotlinFunctionTypeReturningUnitIsAConsumer() {
        ApplicationGraph kotlin = FixtureScans.scan("streamkotlin");
        assertThat(path(kotlin, "ingress:KAFKA orders")).anySatisfy(id -> assertThat(id).endsWith(
                "Warehouse#ship(fixtures.streamkotlin.Order):@PreAuthorize:no-caller"));
    }

    @Test
    void everyFunctionOfACompositionIsOnThePath() {
        ApplicationGraph composed = FixtureScans.scan("streamcompose");
        // The destination is a placeholder, resolved; store's check is reached after validate, with no caller.
        assertThat(path(composed, "ingress:KAFKA orders")).anySatisfy(id -> assertThat(id).endsWith(
                "Repository#save(java.lang.String):@PreAuthorize:no-caller"));
    }

    @Test
    void aCheckEveryFunctionOfACompositionReachesIsReportedOnce() {
        ApplicationGraph audited = FixtureScans.scan("streamaudit");
        assertThat(path(audited, "ingress:KAFKA payments")).filteredOn(id -> id.endsWith(
                "AuditLog#write(java.lang.String):@PreAuthorize:no-caller")).isNotEmpty();
        assertThat(audited.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED)
                .singleElement().satisfies(finding -> assertThat(finding.message())
                        .contains("AuditLog#write", "KAFKA payments delivers a message"));
    }

    private List<Node> nodes(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow()).toList();
    }
}
