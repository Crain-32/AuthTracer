package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;

import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0098: the other forms of a send and of a listener, and what a listener keeps of a message in objects of
 * its own types.
 */
class MessageFormsFixtureTests {

    private static final String SENDER = "messageformssender";
    private static final String LISTENER = "messageformslistener";
    private static final String SENT = "field:fixtures." + SENDER + ".";
    private static final String RECEIVED = "field:fixtures." + LISTENER + ".";

    private final ApplicationGraph sender = FixtureScans.scan(SENDER);
    private final ApplicationGraph listener = FixtureScans.scan(LISTENER);

    @Test
    void aRecordsValueAndABuiltMessagesPayloadAreWhatIsSent() {
        assertThat(flows(sender, send("KAFKA orders.placed"))).containsExactlyInAnyOrder(
                tuple(SENT + "Order.id", SENT + "OrderPlaced.orderId"),
                tuple(SENT + "Order.sku", SENT + "OrderPlaced.sku"),
                tuple(SENT + "Order.total", SENT + "OrderPlaced.total"));
        // The topic is the message's kafka_topic header.
        assertThat(flows(sender, send("KAFKA orders.shipped"))).contains(
                tuple(SENT + "ShipRequest.carrier", SENT + "OrderShipped.carrier"));
        assertThat(send("JMS orders.audit").request()).isEqualTo(new Payload("fixtures." + SENDER + ".OrderAudited",
                false));
        // Without the header, the template's default topic; StreamBridge's binding's destination.
        assertThat(send("KAFKA orders.reminders").request().type()).endsWith(".OrderPlaced");
        assertThat(flows(sender, send("KAFKA orders.refunded"))).contains(
                tuple(SENT + "Order.total", SENT + "RefundIssued.amount"));
        // A copy of a message and sendDefault, both to the default topic; messages and records the method is handed,
        // whose payload isn't read.
        assertThat(flows(sender, send("KAFKA orders.reminders"))).contains(
                tuple(SENT + "Order.total", SENT + "OrderPlaced.total"));
        assertThat(send("JMS orders.forwarded").request()).isNull();
        assertThat(sender.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("Orders#forward", "a ProducerRecord from a parameter"));
    }

    @Test
    void aSendInALambdaCarriesWhatItCapturesFromItsCallers() {
        // What it captures where it is created, what its caller passes there; each line it is handed.
        assertThat(flows(sender, send("KAFKA orders.cancelled"))).containsExactlyInAnyOrder(
                tuple(SENT + "Line.orderId", SENT + "OrderCancelled.orderId"),
                tuple(SENT + "CancelRequest.reason", SENT + "OrderCancelled.reason"),
                tuple(SENT + "CancelRequest.lines", SENT + "OrderCancelled.line"));
    }

    @Test
    void aListenerThatTakesTheRecordTheMessageOrABatchReceivesItsValue() {
        assertThat(listener.nodes(Ingress.class)).filteredOn(ingress -> ingress.request() != null)
                .extracting(Ingress::endpoint, Ingress::request).containsExactlyInAnyOrder(
                        tuple("KAFKA orders.placed", payload("OrderPlaced", false)),
                        tuple("KAFKA orders.shipped", payload("OrderShipped", false)),
                        tuple("KAFKA orders.cancelled", payload("OrderCancelled", true)),
                        tuple("KAFKA orders.refunded", payload("RefundIssued", true)),
                        tuple("KAFKA orders.reminders", payload("OrderPlaced", true)),
                        tuple("KAFKA orders.arrived", payload("OrderShipped", true)),
                        // The @Header after it isn't the payload.
                        tuple("JMS orders.audit", payload("OrderAudited", false)));
        // Raw batches and messages, and a listener that takes nothing, receive nothing AuthTracer names.
        assertThat(listener.nodes(Ingress.class)).filteredOn(ingress -> ingress.request() == null)
                .extracting(Ingress::endpoint)
                .contains("KAFKA orders.legacy", "KAFKA orders.legacy-one", "JMS orders.pings");
    }

    @Test
    void whatAListenerWritesOfThePayloadIsAFlowOnItsPath() {
        assertThat(flows(listener, "ingress:KAFKA orders.placed")).containsExactlyInAnyOrder(
                tuple(RECEIVED + "OrderPlaced.orderId", RECEIVED + "Invoice.order"),
                tuple(RECEIVED + "OrderPlaced.total", RECEIVED + "Invoice.amount"));
        // A setter on an object it loads; a constructor its callee calls with what the listener passes.
        assertThat(flows(listener, "ingress:KAFKA orders.shipped")).containsExactly(
                tuple(RECEIVED + "OrderShipped.carrier", RECEIVED + "Shipment.carrier"));
        assertThat(flows(listener, "ingress:JMS orders.audit")).containsExactlyInAnyOrder(
                tuple(RECEIVED + "OrderAudited.orderId", RECEIVED + "AuditLine.order"),
                tuple(RECEIVED + "OrderAudited.by", RECEIVED + "AuditLine.by"));
        // In a lambda over the batch, into a class whose superclass holds part of it.
        assertThat(flows(listener, "ingress:KAFKA orders.refunded")).contains(
                tuple(RECEIVED + "RefundIssued.amount", RECEIVED + "Credit.amount"));
        // A note made of none of the payload's fields isn't a write.
        assertThat(listener.flows()).noneMatch(flow -> flow.to().contains("Note"));
    }

    @Test
    void whatTheServiceServesOfWhatAListenerWroteComesFromTheSendersFields() {
        List<Exposure> exposures = Exposures.of(new Linker().link(List.of(sender, listener),
                ZipkinTraces.of(List.of())));
        assertThat(field(exposures, "GET /invoices", "amount")).satisfies(amount -> {
            assertThat(amount.sources()).containsExactly(SENDER + "/" + SENT + "Order.total");
            // The listener's write, the message, the sender's build (and the reminders, which carry OrderPlaced too).
            assertThat(amount.lineage()).extracting(Flow::kind).startsWith(Flow.Kind.LOCAL, Flow.Kind.NETWORK,
                    Flow.Kind.LOCAL);
            assertThat(amount.lineage().getFirst().path()).isEqualTo(LISTENER + "/ingress:KAFKA orders.placed");
            // Neither the sender's checks nor the listener's stand in front of the invoices' readers.
            assertThat(amount.requirement()).doesNotContain("ROLE_CLERK");
        });
        // A field no listener writes stays the service's own.
        assertThat(field(exposures, "GET /invoices", "status").sources())
                .containsExactly(LISTENER + "/" + RECEIVED + "Invoice.status");
        assertThat(field(exposures, "GET /shipments/{id}", "carrier").sources())
                .containsExactly(SENDER + "/" + SENT + "ShipRequest.carrier");
        assertThat(field(exposures, "GET /cancellations", "reason").sources())
                .containsExactly(SENDER + "/" + SENT + "CancelRequest.reason");
        assertThat(field(exposures, "GET /credits", "amount").sources())
                .containsExactly(SENDER + "/" + SENT + "Order.total");
        assertThat(field(exposures, "GET /audit", "by")).satisfies(by -> {
            assertThat(by.sources()).containsExactly(SENDER + "/" + SENT + "Order.customer");
            assertThat(by.requirement()).contains("ROLE_AUDITOR");
        });
    }

    @Test
    void aStreamFunctionsInputAndResultAndAStreamBridgeSend() {
        ApplicationGraph stream = FixtureScans.scan("stream");
        assertThat(stream.nodes(Ingress.class)).filteredOn(ingress -> ingress.httpMethod().equals("KAFKA"))
                .extracting(ingress -> ingress.request().type()).containsOnly("fixtures.stream.Order");
        Egress invoices = send(stream, "KAFKA invoices");
        assertThat(stream.flows(invoices.id())).extracting(Flow::from, Flow::to).containsExactlyInAnyOrder(
                tuple("field:fixtures.stream.Order.id", "field:fixtures.stream.Invoice.orderId"),
                tuple("field:fixtures.stream.Order.sku", "field:fixtures.stream.Invoice.sku"));
        assertThat(stream.nodes(Egress.class)).filteredOn(egress -> egress.uriTemplate().equals("orders"))
                .singleElement().satisfies(bridge -> assertThat(bridge.request().type())
                        .isEqualTo("fixtures.stream.Order"));
    }

    private static Exposure field(List<Exposure> exposures, String endpoint, String field) {
        return exposures.stream().filter(exposure -> exposure.endpoint().equals(endpoint)
                && exposure.field().equals(field)).findFirst().orElseThrow();
    }

    private static Payload payload(String type, boolean many) {
        return new Payload("fixtures." + LISTENER + "." + type, many);
    }

    private static List<org.assertj.core.groups.Tuple> flows(ApplicationGraph graph, String path) {
        return graph.flows(path).stream().map(flow -> tuple(flow.from(), flow.to())).toList();
    }

    private static List<org.assertj.core.groups.Tuple> flows(ApplicationGraph graph, Egress egress) {
        return flows(graph, egress.id());
    }

    private Egress send(String endpoint) {
        return send(sender, endpoint);
    }

    private static Egress send(ApplicationGraph graph, String endpoint) {
        return graph.nodes(Egress.class).stream()
                .filter(egress -> (egress.httpMethod() + " " + egress.uriTemplate()).equals(endpoint)).findFirst()
                .orElseThrow();
    }
}
