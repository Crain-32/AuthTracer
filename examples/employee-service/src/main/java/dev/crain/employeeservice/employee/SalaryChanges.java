package dev.crain.employeeservice.employee;

import java.math.BigDecimal;
import java.time.Instant;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/**
 * Publishes every salary change to Kafka, keyed by employee, for the services that keep their own records of salaries
 * (payroll-service). The message says who made the change, but nothing on the topic checks it.
 */
@Component
public class SalaryChanges {

    static final String TOPIC = "employee.salary-changed";

    private final KafkaTemplate<String, SalaryChanged> kafka;

    public SalaryChanges(KafkaTemplate<String, SalaryChanged> kafka) {
        this.kafka = kafka;
    }

    public void publish(long employeeId, BigDecimal previous, BigDecimal current, String changedBy) {
        kafka.send(TOPIC, Long.toString(employeeId), new SalaryChanged(employeeId, previous, current, changedBy,
                Instant.now()));
    }

    public record SalaryChanged(long employeeId, BigDecimal previous, BigDecimal current, String changedBy,
            Instant at) {
    }
}
