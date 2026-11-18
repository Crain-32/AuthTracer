package fixtures.messageformslistener;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.jms.support.JmsHeaders;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0098: listeners that take the record, the message or a batch, and keep what they receive in objects of
 * their own types, which the service serves.
 */
@SpringBootApplication
@EnableMethodSecurity
class MessageFormsListenerApp {
}

record OrderPlaced(long orderId, String sku, BigDecimal total) {
}

record OrderShipped(long orderId, String carrier) {
}

record OrderAudited(long orderId, String by) {
}

record OrderCancelled(long orderId, String reason, Line line) {
}

record Line(long orderId, String sku) {
}

record RefundIssued(long orderId, BigDecimal amount) {
}

record Invoice(long order, BigDecimal amount, String status) {
}

record Note(String text) {
}

record AuditLine(long order, String by) {
}

class Shipment {

    private final long order;
    private String carrier;

    Shipment(long order) {
        this.order = order;
    }

    public long getOrder() {
        return order;
    }

    public String getCarrier() {
        return carrier;
    }

    public void setCarrier(String carrier) {
        this.carrier = carrier;
    }

    public void setTracked(boolean tracked) {
    }

    public void track(String by) {
    }
}

class Entry {

    private final long order;

    Entry(long order) {
        this.order = order;
    }

    public long getOrder() {
        return order;
    }
}

class Credit extends Entry {

    private final BigDecimal amount;

    Credit(long order, BigDecimal amount) {
        super(order);
        this.amount = amount;
    }

    public BigDecimal getAmount() {
        return amount;
    }
}

@Component
class OrderEvents {

    private final List<Invoice> invoices = new CopyOnWriteArrayList<>();
    private final List<Note> notes = new CopyOnWriteArrayList<>();
    private final Map<Long, Shipment> shipments = new ConcurrentHashMap<>();
    private final List<OrderCancelled> cancellations = new CopyOnWriteArrayList<>();
    private final List<Credit> credits = new CopyOnWriteArrayList<>();
    private final AuditTrail audit;

    OrderEvents(AuditTrail audit) {
        this.audit = audit;
    }

    @KafkaListener(topics = "orders.placed")
    void placed(ConsumerRecord<String, OrderPlaced> record) {
        OrderPlaced placed = record.value();
        invoices.add(new Invoice(placed.orderId(), placed.total(), "open"));
        notes.add(new Note("invoice opened"));
    }

    @KafkaListener(topics = "orders.shipped")
    void shipped(Message<OrderShipped> message) {
        Shipment shipment = shipments.get(message.getPayload().orderId());
        shipment.setCarrier(message.getPayload().carrier());
        // Neither is a property the code sets.
        shipment.setTracked(true);
        shipment.track(message.getPayload().carrier());
    }

    @KafkaListener(topics = "orders.cancelled", batch = "true")
    void cancelled(List<OrderCancelled> batch) {
        cancellations.addAll(batch);
    }

    @KafkaListener(topics = "orders.refunded", batch = "true")
    void refunded(List<Message<RefundIssued>> refunds) {
        refunds.forEach(refund -> credits.add(new Credit(refund.getPayload().orderId(),
                refund.getPayload().amount())));
    }

    @KafkaListener(topics = "orders.reminders", batch = "true")
    void reminded(ConsumerRecords<String, OrderPlaced> records) {
    }

    @JmsListener(destination = "orders.audit")
    void audited(OrderAudited audited, @Header(JmsHeaders.MESSAGE_ID) String id) {
        audit.record(audited.orderId(), audited.by());
    }

    @JmsListener(destination = "orders.pings")
    void pinged() {
    }

    @SuppressWarnings("rawtypes")
    @KafkaListener(topics = "orders.legacy", batch = "true")
    void legacy(List batch) {
    }

    @SuppressWarnings("rawtypes")
    @KafkaListener(topics = "orders.legacy-one")
    void legacyOne(Message message) {
    }

    @KafkaListener(topics = "orders.arrived", batch = "true")
    void arrived(OrderShipped[] arrivals) {
    }

    List<Credit> credits() {
        return credits;
    }

    List<Invoice> invoices() {
        return invoices;
    }

    Shipment shipment(long id) {
        return shipments.get(id);
    }

    List<OrderCancelled> cancellations() {
        return cancellations;
    }
}

@Component
class AuditTrail {

    private final List<AuditLine> lines = new CopyOnWriteArrayList<>();

    void record(long order, String by) {
        lines.add(new AuditLine(order, by));
    }

    List<AuditLine> lines() {
        return lines;
    }
}

@RestController
class OrderEventController {

    private final OrderEvents events;
    private final AuditTrail audit;

    OrderEventController(OrderEvents events, AuditTrail audit) {
        this.events = events;
        this.audit = audit;
    }

    @GetMapping("/invoices")
    List<Invoice> invoices() {
        return events.invoices();
    }

    @GetMapping("/shipments/{id}")
    Shipment shipment(@PathVariable long id) {
        return events.shipment(id);
    }

    @GetMapping("/cancellations")
    List<OrderCancelled> cancellations() {
        return events.cancellations();
    }

    @GetMapping("/credits")
    List<Credit> credits() {
        return events.credits();
    }

    @PreAuthorize("hasRole('AUDITOR')")
    @GetMapping("/audit")
    List<AuditLine> audit() {
        return audit.lines();
    }
}
