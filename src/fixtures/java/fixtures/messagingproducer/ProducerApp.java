package fixtures.messagingproducer;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0044: what a service sends to Kafka topics, a RabbitMQ queue (through the default exchange) and a JMS
 * destination.
 */
@SpringBootApplication
class ProducerApp {
}

record Order(Long id, String sku) {
}

@RestController
class OrderController {

    private static final String ORDERS = "orders";

    private final KafkaTemplate<String, Object> kafka;
    private final RabbitTemplate rabbit;
    private final JmsTemplate jms;

    OrderController(KafkaTemplate<String, Object> kafka, RabbitTemplate rabbit, JmsTemplate jms) {
        this.kafka = kafka;
        this.rabbit = rabbit;
        this.jms = jms;
    }

    @PostMapping("/orders")
    Order place(@RequestBody Order order) {
        kafka.send(ORDERS, order);
        kafka.send("metrics.orders", "placed");
        rabbit.convertAndSend("audit", "order placed");
        rabbit.convertAndSend("exchange.events", "audit", "routed by bindings");
        jms.convertAndSend("mailbox", "new order");
        return order;
    }

    @PostMapping("/returns")
    Order returned(@RequestBody Order order) {
        kafka.send("returns", order);
        rabbit.convertAndSend("", "audit", "order returned");
        return order;
    }
}
