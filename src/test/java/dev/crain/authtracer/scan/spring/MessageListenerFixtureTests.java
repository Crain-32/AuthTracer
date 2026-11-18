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
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0044: Kafka, RabbitMQ and JMS listeners as Ingress, template sends as Egress.
 */
class MessageListenerFixtureTests {

    private final ApplicationGraph consumer = FixtureScans.scan("messaging");
    private final ApplicationGraph producer = FixtureScans.scan("messagingproducer");

    @Test
    void listenersAreEntryPointsByTopicQueueAndDestination() {
        assertThat(consumer.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:KAFKA orders",
                "ingress:KAFKA returns", "ingress:KAFKA metrics\\..*", "ingress:RABBIT audit",
                "ingress:JMS mailbox", "ingress:GET /status",
                // A repeated @KafkaListener, in its @KafkaListeners container.
                "ingress:KAFKA replays", "ingress:KAFKA archive");
        // Both handlers of the class-level listener take what arrives on its topic.
        assertThat(consumer.nodes(Ingress.class)).filteredOn(ingress -> ingress.route().equals("events"))
                .extracting(Ingress::endpoint).containsExactlyInAnyOrder("KAFKA events?payload=Created",
                        "KAFKA events?payload=Deleted");
        assertThat(consumer.nodes(Ingress.class)).filteredOn(ingress -> ingress.httpMethod().equals("KAFKA"))
                .allSatisfy(ingress -> assertThat(ingress.response()).isNull());
    }

    @Test
    void queuesAndTopicsInNestedAnnotationsAreEntryPointsToo() {
        assertThat(consumer.nodes(Ingress.class)).extracting(Ingress::id).contains("ingress:RABBIT refunds",
                "ingress:RABBIT disputes", "ingress:KAFKA ledger");
        assertThat(consumer.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message)
                .anySatisfy(message -> assertThat(message).contains("DeclaredListeners#broadcast"));
    }

    @Test
    void consumerGroupsAndClassLevelListenersAreToldApart() {
        ApplicationGraph forms = FixtureScans.scan("listenerforms");
        // Two groups on one topic by their handlers; a class-level listener's handlers by payload type, unless it
        // has only one.
        assertThat(forms.nodes(Ingress.class)).filteredOn(MessageListeners::isListener).extracting(Ingress::id)
                .containsExactlyInAnyOrder("ingress:KAFKA payments?handler=Billing.onPayment",
                        "ingress:KAFKA payments?handler=Bookkeeping.onPayment",
                        "ingress:RABBIT documents?payload=Invoice", "ingress:RABBIT documents?payload=CreditNote",
                        "ingress:KAFKA notices");
        // An anonymous queue has no name to link by, also when its empty name is spelled out.
        assertThat(forms.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).singleElement()
                .satisfies(message -> assertThat(message).contains("Alerts#alert"));
    }

    @Test
    void requestsThatWaitForTheirReplyAndHandBuiltMessagesAreSendsToo() {
        ApplicationGraph sends = FixtureScans.scan("sendforms");
        // Destinations held in parameters and a named exchange's routing are destinations AuthTracer can't read
        // (decision 0082), one per template; a @Value no file sets keeps its placeholder; reads are no sends.
        assertThat(sends.nodes(Egress.class)).extracting(Egress::client, Egress::httpMethod, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("RabbitTemplate", "RABBIT", "pricing"),
                        tuple("AmqpTemplate", "RABBIT", "archive"), tuple("JmsTemplate", "JMS", "orders.in"),
                        tuple("JmsMessagingTemplate", "JMS", "stock"), tuple("RabbitTemplate", "RABBIT", "quotes"),
                        tuple("KafkaTemplate", "KAFKA", "${app.topic}"), tuple("JmsTemplate", "JMS", "?"),
                        tuple("RabbitTemplate", "RABBIT", "?"), tuple("KafkaTemplate", "KAFKA", "?"));
        assertThat(path(sends, "ingress:POST /quotes")).filteredOn(id -> id.startsWith("egress:")).hasSize(5);
        assertThat(sends.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("the template's default topic"));
        assertThat(sends.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.OPAQUE_CONFIG)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("an exchange from a parameter"));
    }

    @Test
    void aBrokerDeliversWithoutTheRequestRules() {
        List<AuthorizationLocation> orders = checks("ingress:KAFKA orders");
        assertThat(orders).extracting(AuthorizationLocation::mechanism).containsExactly("@PreAuthorize (no caller)");
        assertThat(checks("ingress:JMS mailbox")).isEmpty();
        assertThat(checks("ingress:GET /status")).extracting(AuthorizationLocation::mechanism)
                .containsExactly("authorizeHttpRequests");
    }

    @Test
    void aMethodCheckAListenerReachesHasNoCaller() {
        List<Finding> noCaller = consumer.findings().stream()
                .filter(finding -> finding.kind() == Finding.Kind.ALWAYS_DENIED).toList();
        // Only the orders listener: returns sets a SecurityContext first, and permitAll() asks for no caller.
        assertThat(noCaller).singleElement().satisfies(finding -> {
            assertThat(finding.message()).contains("KAFKA orders", "Fulfilment#ship",
                    "AuthenticationCredentialsNotFoundException");
            assertThat(finding.location().className()).isEqualTo("fixtures.messaging.Fulfilment");
        });
        // On the orders listener's path the check denies; returns, which sets a context first, keeps the role.
        assertThat(checks("ingress:KAFKA orders").getFirst().requirement().kind())
                .isEqualTo(Requirement.Kind.DENY_ALL);
        assertThat(checks("ingress:KAFKA returns")).singleElement().satisfies(check -> {
            assertThat(check.mechanism()).isEqualTo("@PreAuthorize");
            assertThat(check.requirement().authorities()).containsExactly("ROLE_WAREHOUSE");
        });
    }

    @Test
    void sendsAreEgressToTheirTopics() {
        assertThat(producer.nodes(Egress.class)).extracting(Egress::client, Egress::httpMethod, Egress::uriTemplate)
                .containsExactlyInAnyOrder(tuple("KafkaTemplate", "KAFKA", "orders"),
                        tuple("KafkaTemplate", "KAFKA", "metrics.orders"),
                        tuple("RabbitTemplate", "RABBIT", "audit"), tuple("JmsTemplate", "JMS", "mailbox"),
                        // The default exchange routes by queue name; a named exchange by bindings it doesn't see.
                        tuple("KafkaTemplate", "KAFKA", "returns"), tuple("RabbitTemplate", "RABBIT", "audit"),
                        tuple("RabbitTemplate", "RABBIT", "?"));
        assertThat(path(producer, "ingress:POST /orders")).filteredOn(id -> id.startsWith("egress:")).hasSize(5);
        assertThat(producer.findings()).extracting(Finding::message).anySatisfy(message -> assertThat(message)
                .contains("the bindings of the exchange exchange.events for the routing key audit"));
    }

    @Test
    void producersLinkToTheListenersOfTheirTopics() {
        SystemGraph system = new Linker().link(List.of(producer, consumer), ZipkinTraces.of(List.of()));
        assertThat(system.links()).extracting(Edge::to).containsOnly("messaging/ingress:KAFKA orders",
                "messaging/ingress:KAFKA returns",
                "messaging/ingress:KAFKA metrics\\..*", "messaging/ingress:RABBIT audit",
                "messaging/ingress:JMS mailbox");
        // Fixed-route messages carry no caller, so no finding about whose credentials the checks see.
        assertThat(system.findings()).noneMatch(finding -> finding.kind() == Finding.Kind.BYPASSED);
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(consumer, ingress).stream().map(id -> consumer.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast).toList();
    }
}
