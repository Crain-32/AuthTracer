package dev.crain.payrollservice.payroll;

import java.time.Duration;

import dev.crain.payrollservice.employeeservice.EmployeeDto;
import dev.crain.payrollservice.employeeservice.EmployeeServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.converter.RecordMessageConverter;
import org.springframework.kafka.support.converter.StringJacksonJsonMessageConverter;
import org.springframework.stereotype.Component;

/**
 * employee-service's salary changes, from Kafka, into the ledger for the next pay run. A message has no caller:
 * the change is taken as employee-service published it, and the employee's name is read from employee-service with
 * payroll-service's own token.
 */
@Component
public class SalaryChangeListener {

    private static final Logger log = LoggerFactory.getLogger(SalaryChangeListener.class);

    private static final Duration DIRECTORY_TIMEOUT = Duration.ofSeconds(10);

    private final PayrollLedger ledger;
    private final EmployeeServiceClient employeeService;

    public SalaryChangeListener(PayrollLedger ledger, EmployeeServiceClient employeeService) {
        this.ledger = ledger;
        this.employeeService = employeeService;
    }

    @KafkaListener(topics = "employee.salary-changed", groupId = "payroll-service")
    public void salaryChanged(SalaryChange change) {
        log.info("employee.salary-changed: employee {} {} -> {} by {}", change.employeeId(), change.previous(),
                change.current(), change.changedBy());
        // A listener's thread may wait: the pay run needs the name before the change is kept.
        EmployeeDto employee = employeeService.employeeAsPayroll(change.employeeId()).block(DIRECTORY_TIMEOUT);
        ledger.record(PayrollChange.of(change, employee));
    }

    @Configuration
    static class Messaging {

        /**
         * Reads each record's JSON into the listener's parameter type.
         */
        @Bean
        RecordMessageConverter recordMessageConverter() {
            return new StringJacksonJsonMessageConverter();
        }
    }
}
