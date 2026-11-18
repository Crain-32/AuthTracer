package fixtures.listenerforms;

import org.springframework.amqp.core.ExchangeTypes;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitHandler;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.kafka.annotation.KafkaHandler;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Decision 0044, the other ways listeners are written: two consumer groups on one topic, a class-level RabbitMQ
 * listener with a handler per payload type, a class-level Kafka listener with a single handler, and a subscriber's
 * anonymous queue, its empty name spelled out.
 */
@SpringBootApplication
class ListenerFormsApp {
}

record Invoice(Long id) {
}

record CreditNote(Long id) {
}

@Component
class Billing {

    @KafkaListener(topics = "payments", groupId = "billing")
    public void onPayment(String payment) {
    }
}

@Component
class Bookkeeping {

    @KafkaListener(topics = "payments", groupId = "bookkeeping")
    public void onPayment(String payment) {
    }
}

@Component
@RabbitListener(queues = "documents")
class Documents {

    @RabbitHandler
    public void invoice(Invoice invoice) {
    }

    @RabbitHandler
    public void creditNote(CreditNote note) {
    }
}

@Component
@KafkaListener(topics = "notices")
class Notices {

    @KafkaHandler
    public void notice(String notice) {
    }
}

@Component
class Alerts {

    @RabbitListener(bindings = @QueueBinding(value = @Queue(value = "", exclusive = "true", autoDelete = "true"),
            exchange = @Exchange(value = "alerts", type = ExchangeTypes.FANOUT)))
    public void alert(String alert) {
    }
}
