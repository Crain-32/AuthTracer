package fixtures.events;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Application events: the listeners run on the publisher's thread, so their checks and calls are on its path.
 */
@SpringBootApplication
@EnableMethodSecurity
class EventsApp {
}

record OrderPlaced(Long id) {
}

@Service
class Audit {

    @PreAuthorize("hasRole('SALES')")
    public void record(Long order) {
    }
}

@RestController
class OrderController {

    private final ApplicationEventPublisher events;

    OrderController(ApplicationEventPublisher events) {
        this.events = events;
    }

    @PostMapping("/orders/{id}")
    void place(@PathVariable Long id) {
        events.publishEvent(new OrderPlaced(id));
    }
}

@Component
class OrderListeners {

    private final Audit audit;

    private final RestClient shipping = RestClient.create("http://localhost:8093");

    OrderListeners(Audit audit) {
        this.audit = audit;
    }

    @EventListener
    void onPlaced(OrderPlaced placed) {
        audit.record(placed.id());
    }

    @TransactionalEventListener
    void afterCommit(OrderPlaced placed) {
        shipping.post().uri("/shipments/{id}", placed.id()).retrieve().toBodilessEntity();
    }

    @EventListener
    void unrelated(String text) {
        audit.record(0L);
    }
}
