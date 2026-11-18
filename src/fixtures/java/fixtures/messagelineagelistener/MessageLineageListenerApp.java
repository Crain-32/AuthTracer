package fixtures.messagelineagelistener;

import java.math.BigDecimal;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0090: what a listener receives is its payload parameter's fields, which the senders' messages fill; a
 * ledger that keeps the changes it receives and serves them.
 */
@SpringBootApplication
@EnableMethodSecurity
class MessageLineageListenerApp {
}

record SalaryChange(long employeeId, BigDecimal previous, BigDecimal current, String changedBy) {
}

record AuditEntry(String employee, String what) {
}

record Departure(long employeeId, String name) {
}

@Component
class Ledger {

    private final List<SalaryChange> changes = new CopyOnWriteArrayList<>();

    @KafkaListener(topics = "employee.salary-changed", groupId = "payroll")
    void salaryChanged(SalaryChange change) {
        changes.add(change);
    }

    @RabbitListener(queues = "audit.viewed")
    void viewed(@Header("amqp_receivedRoutingKey") String key, @Payload AuditEntry entry) {
    }

    @KafkaListener(topics = "employee.salary-changed", groupId = "raw")
    void raw(ConsumerRecord<String, String> record) {
    }

    @JmsListener(destination = "employee.left")
    void left(Departure departure) {
    }

    List<SalaryChange> changes() {
        return changes;
    }
}

@RestController
class LedgerController {

    private final Ledger ledger;

    LedgerController(Ledger ledger) {
        this.ledger = ledger;
    }

    @GetMapping("/ledger/changes")
    List<SalaryChange> changes() {
        return ledger.changes();
    }
}
