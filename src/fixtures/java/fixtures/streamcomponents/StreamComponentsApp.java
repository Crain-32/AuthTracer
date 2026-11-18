package fixtures.streamcomponents;

import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

/**
 * Decision 0047: functions declared as components, named as Spring names their beans.
 */
@SpringBootApplication
@EnableMethodSecurity
class StreamComponentsApp {
}

record Order(Long id) {
}

@Service
class Ledger {

    @PreAuthorize("hasRole('AUDITOR')")
    public void record(Order order) {
    }
}

@Component
class Enrich implements Function<Order, Order> {

    @Override
    public Order apply(Order order) {
        return new Order(order.id() + 1);
    }
}

@Component("audit")
class AuditConsumer implements Consumer<Order> {

    private final Ledger ledger;

    AuditConsumer(Ledger ledger) {
        this.ledger = ledger;
    }

    @Override
    public void accept(Order order) {
        ledger.record(order);
    }
}

/**
 * Named by its stereotype's value, as {@code @Component("audit")} names its bean.
 */
@Service("archive")
class ArchiveConsumer implements Consumer<Order> {

    @Override
    public void accept(Order order) {
    }
}
