package fixtures.messageformssender;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.jms.core.JmsMessagingTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0098: the other ways a message is sent: a {@code ProducerRecord}, a {@code Message} built with
 * {@code MessageBuilder} (its topic a header, or the template's default) or as a {@code GenericMessage}, a send in a
 * lambda that captures what its method was passed, and {@code StreamBridge}.
 */
@SpringBootApplication
@EnableMethodSecurity
class MessageFormsSenderApp {
}

record Order(long id, String sku, BigDecimal total, String customer) {
}

record ShipRequest(String carrier) {
}

record CancelRequest(String reason, List<Line> lines) {
}

record Line(long orderId, String sku) {
}

record OrderPlaced(long orderId, String sku, BigDecimal total) {
}

record OrderShipped(long orderId, String carrier) {
}

record OrderAudited(long orderId, String by) {
}

record OrderCancelled(long orderId, String reason, Line line) {
}

record RefundIssued(long orderId, BigDecimal amount) {
}

@Service
class Orders {

    private final Map<Long, Order> orders = Map.of(1L, new Order(1, "book", BigDecimal.TEN, "ada"));
    private final KafkaTemplate<String, Object> kafka;
    private final JmsMessagingTemplate jms;
    private final StreamBridge bridge;

    Orders(KafkaTemplate<String, Object> kafka, JmsMessagingTemplate jms, StreamBridge bridge) {
        this.kafka = kafka;
        this.jms = jms;
        this.bridge = bridge;
    }

    @PreAuthorize("hasRole('CLERK')")
    void place(long id) {
        Order order = orders.get(id);
        kafka.send(new ProducerRecord<>("orders.placed", order.sku(),
                new OrderPlaced(order.id(), order.sku(), order.total())));
    }

    void ship(long id, ShipRequest request) {
        Order order = orders.get(id);
        kafka.send(MessageBuilder.withPayload(new OrderShipped(order.id(), request.carrier()))
                .setHeader(KafkaHeaders.TOPIC, "orders.shipped").build());
        jms.send("orders.audit", new GenericMessage<>(new OrderAudited(order.id(), order.customer())));
    }

    void cancelAll(CancelRequest request) {
        cancel(request.reason(), request.lines());
    }

    private void cancel(String reason, List<Line> lines) {
        // The lambda captures the template and the reason, and is handed each line.
        KafkaTemplate<String, Object> template = kafka;
        lines.forEach(line -> template.send("orders.cancelled", new OrderCancelled(line.orderId(), reason, line)));
    }

    void refund(long id) {
        Order order = orders.get(id);
        bridge.send("refunds-out-0", MessageBuilder.createMessage(new RefundIssued(order.id(), order.total()),
                new MessageHeaders(Map.of())));
    }

    void remind(long id) {
        Order order = orders.get(id);
        Message<OrderPlaced> reminder = MessageBuilder.withPayload(new OrderPlaced(order.id(), order.sku(),
                order.total())).build();
        kafka.send(MessageBuilder.fromMessage(reminder).setHeader(KafkaHeaders.KEY, order.sku()).build());
        kafka.sendDefault(new OrderPlaced(order.id(), order.sku(), order.total()));
    }

    void forward(Message<OrderPlaced> message, ProducerRecord<String, Object> record) {
        // Built elsewhere: what they hold isn't read.
        jms.send("orders.forwarded", message);
        kafka.send(record);
    }
}

@RestController
class OrderController {

    private final Orders orders;

    OrderController(Orders orders) {
        this.orders = orders;
    }

    @PostMapping("/orders/{id}/place")
    void place(@PathVariable long id) {
        orders.place(id);
    }

    @PostMapping("/orders/{id}/ship")
    void ship(@PathVariable long id, @RequestBody ShipRequest request) {
        orders.ship(id, request);
    }

    @PostMapping("/orders/cancel")
    void cancel(@RequestBody CancelRequest request) {
        orders.cancelAll(request);
    }

    @PostMapping("/orders/{id}/refund")
    void refund(@PathVariable long id) {
        orders.refund(id);
    }

    @PostMapping("/orders/{id}/remind")
    void remind(@PathVariable long id) {
        orders.remind(id);
    }

    @PostMapping("/orders/forward")
    void forward(@RequestBody OrderPlaced placed) {
        orders.forward(MessageBuilder.withPayload(placed).build(), new ProducerRecord<>("orders.placed", placed));
    }
}
