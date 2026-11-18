package fixtures.messaging;

import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.kafka.annotation.KafkaHandler;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.annotation.TopicPartition;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0044: what arrives from Kafka, RabbitMQ and JMS. The listeners have no caller, so the warehouse check
 * fails for the orders listener; the returns listener sets a SecurityContext first.
 */
@SpringBootApplication
@EnableMethodSecurity
class MessagingApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());
        return http.build();
    }
}

record Order(Long id, String sku) {
}

record Created(Long id) {
}

record Deleted(Long id) {
}

@Service
class Fulfilment {

    @PreAuthorize("hasRole('WAREHOUSE')")
    public void ship(Order order) {
    }

    @PreAuthorize("permitAll()")
    public void log(String line) {
    }
}

@Component
class OrderListener {

    private final Fulfilment fulfilment;

    OrderListener(Fulfilment fulfilment) {
        this.fulfilment = fulfilment;
    }

    @KafkaListener(topics = "orders")
    public void onOrder(Order order) {
        fulfilment.ship(order);
    }

    @KafkaListener(topics = "returns")
    public void onReturn(Order order) {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "returns", null, AuthorityUtils.createAuthorityList("ROLE_WAREHOUSE")));
        fulfilment.ship(order);
    }

    @KafkaListener(topicPattern = "metrics\\..*")
    public void onMetric(String metric) {
        fulfilment.log(metric);
    }
}

@Component
@KafkaListener(topics = "events")
class EventListener {

    @KafkaHandler
    public void created(Created created) {
    }

    @KafkaHandler
    public void deleted(Deleted deleted) {
    }
}

@Component
class Replays {

    @KafkaListener(topics = "replays")
    @KafkaListener(topics = "archive")
    public void replay(String event) {
    }
}

@Component
class AuditListener {

    @RabbitListener(queues = "${app.audit-queue}")
    public void record(String entry) {
    }
}

/**
 * Queues and topics named in nested annotations; a broker-named queue has no name to read.
 */
@Component
class DeclaredListeners {

    @RabbitListener(bindings = @QueueBinding(value = @Queue("refunds"), exchange = @Exchange("payments")))
    public void refund(String refund) {
    }

    @RabbitListener(queuesToDeclare = @Queue(name = "disputes"))
    public void dispute(String dispute) {
    }

    @KafkaListener(topicPartitions = @TopicPartition(topic = "ledger", partitions = "0"))
    public void ledger(String entry) {
    }

    @RabbitListener(bindings = @QueueBinding(value = @Queue, exchange = @Exchange("broadcasts")))
    public void broadcast(String message) {
    }
}

@Component
class Mailbox {

    @JmsListener(destination = "mailbox")
    public void receive(String mail) {
    }
}

@RestController
class StatusController {

    @GetMapping("/status")
    String status() {
        return "ok";
    }

    // Never runs: nothing enables scheduling.
    @org.springframework.scheduling.annotation.Scheduled(fixedRate = 1000)
    void poll() {
    }
}
