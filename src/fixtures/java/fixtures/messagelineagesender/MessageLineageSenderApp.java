package fixtures.messagelineagesender;

import java.math.BigDecimal;
import java.util.Map;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0090: what a send carries, built from the fields the request read on its way there: a Kafka event made
 * in a publisher from what its caller passes it, and a RabbitMQ message made where it is sent.
 */
@SpringBootApplication
@EnableMethodSecurity
class MessageLineageSenderApp {
}

record Employee(long id, String name, BigDecimal salary) {
}

record SalaryUpdate(BigDecimal salary) {
}

record SalaryChanged(long employeeId, BigDecimal previous, BigDecimal current, String changedBy) {
}

record Viewed(String employee, String what) {
}

record Left(long employeeId, String name) {
}

@Component
class SalaryChanges {

    private final KafkaTemplate<String, SalaryChanged> kafka;

    SalaryChanges(KafkaTemplate<String, SalaryChanged> kafka) {
        this.kafka = kafka;
    }

    void publish(long employeeId, BigDecimal previous, BigDecimal current, String changedBy) {
        kafka.send("employee.salary-changed", Long.toString(employeeId),
                new SalaryChanged(employeeId, previous, current, changedBy));
    }
}

@Service
class Employees {

    private final Map<Long, Employee> employees = Map.of(1L, new Employee(1, "Ada", BigDecimal.TEN));
    private final SalaryChanges changes;
    private final RabbitTemplate rabbit;
    private final JmsTemplate jms;

    Employees(SalaryChanges changes, RabbitTemplate rabbit, JmsTemplate jms) {
        this.changes = changes;
        this.rabbit = rabbit;
        this.jms = jms;
    }

    @PreAuthorize("hasRole('ADMIN')")
    Employee raise(long id, SalaryUpdate update) {
        Employee employee = employees.get(id);
        changes.publish(employee.id(), employee.salary(), update.salary(), "admin");
        return new Employee(employee.id(), employee.name(), update.salary());
    }

    Employee view(long id) {
        Employee employee = employees.get(id);
        rabbit.convertAndSend("audit.viewed", new Viewed(employee.name(), "salary"));
        return employee;
    }

    void leave(long id) {
        Employee employee = employees.get(id);
        jms.convertAndSend("employee.left", new Left(employee.id(), employee.name()));
    }
}

@RestController
class EmployeeController {

    private final Employees employees;

    EmployeeController(Employees employees) {
        this.employees = employees;
    }

    @PutMapping("/employees/{id}/salary")
    Employee raise(@PathVariable long id, @RequestBody SalaryUpdate update) {
        return employees.raise(id, update);
    }

    @GetMapping("/employees/{id}")
    Employee view(@PathVariable long id) {
        return employees.view(id);
    }

    @DeleteMapping("/employees/{id}")
    void leave(@PathVariable long id) {
        employees.leave(id);
    }
}
