package fixtures.messageconfig;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.cloud.stream.function.StreamOperations;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Destinations a service takes from its configuration: Kafka topics in {@code @Value} fields and constructor
 * parameters (one with a default, one no file sets), a {@code @ConfigurationProperties} record's queue and topic, a
 * JMS destination in a property, and a {@code StreamOperations} field's binding.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
class MessageConfigApp {
}

record Event(String id) {
}

@ConfigurationProperties("app.messaging")
record MessagingProperties(String auditQueue, @DefaultValue("payments") String paymentsTopic) {
}

@Component
class Publishers {

    private final KafkaTemplate<String, Object> kafka;
    private final RabbitTemplate rabbit;
    private final JmsTemplate jms;
    private final StreamOperations stream;
    private final MessagingProperties messaging;
    private final String shipmentsTopic;

    @Value("${app.orders-topic}")
    private String ordersTopic;

    @Value("${app.unset-topic}")
    private String unsetTopic;

    @Value("${app.invoice-queue}")
    private String invoiceQueue;

    Publishers(KafkaTemplate<String, Object> kafka, RabbitTemplate rabbit, JmsTemplate jms, StreamOperations stream,
            MessagingProperties messaging, @Value("${app.shipments-topic:shipments}") String shipmentsTopic) {
        this.kafka = kafka;
        this.rabbit = rabbit;
        this.jms = jms;
        this.stream = stream;
        this.messaging = messaging;
        this.shipmentsTopic = shipmentsTopic;
    }

    void publish(Event event) {
        kafka.send(ordersTopic, event);
        kafka.send(shipmentsTopic, event);
        kafka.send(messaging.paymentsTopic(), event);
        kafka.send(unsetTopic, event);
        rabbit.convertAndSend(messaging.auditQueue(), event);
        jms.convertAndSend(invoiceQueue, event);
        stream.send("events-out-0", event);
    }
}

@Component
class UnsetListener {

    @KafkaListener(topics = "${app.unset-topic}")
    void unset(Event event) {
    }
}

@RestController
class EventController {

    private final Publishers publishers;

    EventController(Publishers publishers) {
        this.publishers = publishers;
    }

    @PostMapping("/events")
    void publish(@RequestBody Event event) {
        publishers.publish(event);
    }
}
