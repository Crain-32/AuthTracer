package fixtures.sendforms;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.core.MessageBuilder;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jms.core.JmsMessagingTemplate;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0044, the other ways a service sends: a request that waits for its reply, a message built by hand, a
 * message post-processor, destinations held in variables, and calls that read from a destination rather than send.
 */
@SpringBootApplication
class SendFormsApp {
}

record Quote(String sku) {
}

@RestController
class QuoteController {

    private final KafkaTemplate<String, Object> kafka;
    private final RabbitTemplate rabbit;
    private final AmqpTemplate amqp;
    private final JmsTemplate jms;
    private final JmsMessagingTemplate messaging;

    @Value("${app.topic}")
    private String topic;

    QuoteController(KafkaTemplate<String, Object> kafka, RabbitTemplate rabbit, AmqpTemplate amqp, JmsTemplate jms,
            JmsMessagingTemplate messaging) {
        this.kafka = kafka;
        this.rabbit = rabbit;
        this.amqp = amqp;
        this.jms = jms;
        this.messaging = messaging;
    }

    @PostMapping("/quotes")
    Object quote(@RequestBody Quote quote) {
        rabbit.convertAndSend("pricing", quote, message -> {
            message.getMessageProperties().setPriority(5);
            return message;
        });
        amqp.send("archive", MessageBuilder.withBody(quote.sku().getBytes()).build());
        jms.send("orders.in", session -> session.createTextMessage(quote.sku()));
        messaging.convertSendAndReceive("stock", quote, String.class);
        return rabbit.convertSendAndReceive("quotes", quote);
    }

    @PostMapping("/quotes/routed")
    void routed(@RequestBody Quote quote, @RequestParam String queue, @RequestParam String exchange) {
        // Where these go is only known at run time.
        kafka.send(topic, quote);
        // Boot's spring.kafka.template.default-topic, which no file sets.
        kafka.sendDefault(quote);
        jms.convertAndSend(queue, quote);
        rabbit.convertAndSend(queue, quote);
        rabbit.convertAndSend("", queue, quote);
        rabbit.convertAndSend(exchange, "pricing", quote);
    }

    @GetMapping("/quotes/pending")
    Object pending() {
        kafka.partitionsFor("quotes");
        jms.receiveAndConvert("replies");
        return rabbit.receiveAndConvert("quotes");
    }
}
