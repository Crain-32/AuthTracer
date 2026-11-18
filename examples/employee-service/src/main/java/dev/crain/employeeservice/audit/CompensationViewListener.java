package dev.crain.employeeservice.audit;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

/**
 * profile-service's audit events, from RabbitMQ. A message has no caller: the listener records whatever viewer the
 * event names.
 */
@Component
public class CompensationViewListener {

    static final String QUEUE = "audit.compensation-viewed";

    private static final Logger log = LoggerFactory.getLogger(CompensationViewListener.class);

    private final AuditService auditService;

    public CompensationViewListener(AuditService auditService) {
        this.auditService = auditService;
    }

    @RabbitListener(queues = QUEUE)
    public void compensationViewed(CompensationViewed event) {
        log.info("{}: employee {} viewed by {}", QUEUE, event.employeeId(), event.viewedBy());
        auditService.recordCompensationView(event.employeeId(), event.viewedBy(), event.at());
    }

    public record CompensationViewed(long employeeId, String viewedBy, Instant at) {
    }

    @Configuration
    static class Messaging {

        /**
         * The consumer owns the queue; publishers send to it through the default exchange.
         */
        @Bean
        Queue compensationViewedQueue() {
            return new Queue(QUEUE);
        }

        @Bean
        MessageConverter jsonMessageConverter() {
            return new JacksonJsonMessageConverter();
        }
    }
}
