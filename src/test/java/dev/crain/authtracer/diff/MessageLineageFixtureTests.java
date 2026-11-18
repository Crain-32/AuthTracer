package dev.crain.authtracer.diff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import java.util.List;

import dev.crain.authtracer.diff.Exposures.Exposure;
import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Flow;
import dev.crain.authtracer.graph.Ingress;
import dev.crain.authtracer.graph.Payload;
import dev.crain.authtracer.graph.SystemGraph;
import dev.crain.authtracer.link.Linker;
import dev.crain.authtracer.link.ZipkinTraces;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0090: a message's fields, from what the sender built it of to what the listener receives.
 */
class MessageLineageFixtureTests {

    private static final String SENDER = "messagelineagesender";
    private static final String LISTENER = "messagelineagelistener";
    private static final String SENT = "field:fixtures." + SENDER + ".";
    private static final String RECEIVED = "field:fixtures." + LISTENER + ".";

    private final ApplicationGraph sender = FixtureScans.scan(SENDER);
    private final ApplicationGraph listener = FixtureScans.scan(LISTENER);

    @Test
    void aSendCarriesWhatItIsBuiltOfOnTheWayThere() {
        // The publisher's parameters are what the service passes it: the employee's fields and the request's.
        Egress kafka = send("KAFKA");
        assertThat(kafka.request()).isEqualTo(new Payload("fixtures." + SENDER + ".SalaryChanged", false));
        assertThat(sender.flows(kafka.id())).extracting(Flow::from, Flow::to).containsExactlyInAnyOrder(
                tuple(SENT + "Employee.id", SENT + "SalaryChanged.employeeId"),
                tuple(SENT + "Employee.salary", SENT + "SalaryChanged.previous"),
                tuple(SENT + "SalaryUpdate.salary", SENT + "SalaryChanged.current"));
        Egress rabbit = send("RABBIT");
        assertThat(sender.flows(rabbit.id())).extracting(Flow::from, Flow::to)
                .containsExactly(tuple(SENT + "Employee.name", SENT + "Viewed.employee"));
        assertThat(sender.flows(send("JMS").id())).extracting(Flow::from, Flow::to).containsExactlyInAnyOrder(
                tuple(SENT + "Employee.id", SENT + "Left.employeeId"),
                tuple(SENT + "Employee.name", SENT + "Left.name"));
        // The constant has no source, but is a field of the message all the same.
        assertThat(sender.nodes(Field.class)).extracting(Field::id).contains(SENT + "SalaryChanged.changedBy");
    }

    @Test
    void aListenerReceivesItsPayloadParameter() {
        assertThat(listener.nodes(Ingress.class)).filteredOn(ingress -> ingress.request() != null)
                .extracting(Ingress::endpoint, ingress -> ingress.request().type()).containsExactlyInAnyOrder(
                        tuple("KAFKA employee.salary-changed?handler=Ledger.salaryChanged",
                                "fixtures." + LISTENER + ".SalaryChange"),
                        // The @Payload, not the header.
                        tuple("RABBIT audit.viewed", "fixtures." + LISTENER + ".AuditEntry"),
                        tuple("JMS employee.left", "fixtures." + LISTENER + ".Departure"));
        assertThat(listener.nodes(Field.class)).extracting(Field::id).contains(RECEIVED + "AuditEntry.employee");
    }

    @Test
    void theLinkerJoinsWhatIsSentToWhatIsReceivedByName() {
        SystemGraph system = link();
        String kafka = SystemGraph.qualify(SENDER, send("KAFKA").id());
        assertThat(system.flows()).filteredOn(flow -> flow.kind() == Flow.Kind.NETWORK)
                .extracting(Flow::path, Flow::from, Flow::to).contains(
                        tuple(kafka, SENDER + "/" + SENT + "SalaryChanged.previous",
                                LISTENER + "/" + RECEIVED + "SalaryChange.previous"),
                        tuple(kafka, SENDER + "/" + SENT + "SalaryChanged.changedBy",
                                LISTENER + "/" + RECEIVED + "SalaryChange.changedBy"),
                        tuple(SystemGraph.qualify(SENDER, send("RABBIT").id()),
                                SENDER + "/" + SENT + "Viewed.employee", LISTENER + "/" + RECEIVED
                                        + "AuditEntry.employee"),
                        tuple(SystemGraph.qualify(SENDER, send("JMS").id()), SENDER + "/" + SENT + "Left.name",
                                LISTENER + "/" + RECEIVED + "Departure.name"));
        // The listener that takes the whole record receives no payload AuthTracer reads.
        assertThat(system.flows()).filteredOn(flow -> flow.kind() == Flow.Kind.NETWORK)
                .noneMatch(flow -> flow.to().contains("ConsumerRecord"));
    }

    @Test
    void whatTheListenerKeepsAndServesComesFromTheSendersFields() {
        List<Exposure> served = Exposures.of(link()).stream()
                .filter(exposure -> exposure.endpoint().equals("GET /ledger/changes")).toList();
        assertThat(served).filteredOn(exposure -> exposure.field().equals("previous")).singleElement()
                .satisfies(previous -> {
                    assertThat(previous.sources()).containsExactly(SENDER + "/" + SENT + "Employee.salary");
                    assertThat(previous.lineage()).extracting(Flow::kind)
                            .containsExactly(Flow.Kind.NETWORK, Flow.Kind.LOCAL);
                    // A message has no caller: the sender's admin check doesn't stand in front of the ledger's readers.
                    assertThat(previous.requirement()).doesNotContain("ROLE_ADMIN");
                });
        // A constant the sender wrote has no source in it: the field is its own.
        assertThat(served).filteredOn(exposure -> exposure.field().equals("changedBy")).singleElement()
                .satisfies(changedBy -> assertThat(changedBy.sources())
                        .containsExactly(SENDER + "/" + SENT + "SalaryChanged.changedBy"));
    }

    private SystemGraph link() {
        return new Linker().link(List.of(sender, listener), ZipkinTraces.of(List.of()));
    }

    private Egress send(String kind) {
        return sender.nodes(Egress.class).stream().filter(egress -> egress.httpMethod().equals(kind)).findFirst()
                .orElseThrow();
    }
}
