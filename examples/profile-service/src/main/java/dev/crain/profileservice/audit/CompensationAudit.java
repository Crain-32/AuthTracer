package dev.crain.profileservice.audit;

import java.time.Instant;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * Tells employee-service's audit, over RabbitMQ, who viewed an employee's compensation. The queue is
 * employee-service's; the default exchange routes to it by name.
 */
@Component
public class CompensationAudit {

    private final AmqpTemplate rabbit;

    public CompensationAudit(AmqpTemplate rabbit) {
        this.rabbit = rabbit;
    }

    public void viewed(long employeeId, String viewedBy) {
        rabbit.convertAndSend("audit.compensation-viewed", new CompensationViewed(employeeId, viewedBy, Instant.now()));
    }

    public record CompensationViewed(long employeeId, String viewedBy, Instant at) {
    }

    @Configuration
    static class Messaging {

        @Bean
        MessageConverter jsonMessageConverter() {
            return new JacksonJsonMessageConverter();
        }
    }
}
