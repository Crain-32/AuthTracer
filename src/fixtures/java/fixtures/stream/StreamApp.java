package fixtures.stream;

import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0047: Spring Cloud Stream functions on the Kafka binder. Two functions consume orders; one produces
 * invoices; a supplier is polled; an HTTP endpoint sends through StreamBridge. The unbound consumer isn't in the
 * definition.
 */
@SpringBootApplication
@EnableMethodSecurity
class StreamApp {

    @Bean
    Consumer<Order> shipOrders(Fulfilment fulfilment) {
        return order -> fulfilment.ship(order);
    }

    @Bean
    Function<Order, Invoice> invoice() {
        return order -> new Invoice(order.id(), order.sku());
    }

    @Bean
    Supplier<Heartbeat> heartbeat() {
        return () -> new Heartbeat("up");
    }

    @Bean
    Consumer<String> unbound() {
        return line -> {
        };
    }
}

record Order(Long id, String sku) {
}

record Invoice(Long orderId, String sku) {
}

record Heartbeat(String status) {
}

@Service
class Fulfilment {

    @PreAuthorize("hasRole('WAREHOUSE')")
    public void ship(Order order) {
    }
}

@RestController
class OrderController {

    private final StreamBridge bridge;

    OrderController(StreamBridge bridge) {
        this.bridge = bridge;
    }

    @PostMapping("/orders")
    void place(@RequestBody Order order) {
        bridge.send("placeOrder-out-0", order);
        bridge.send("audit", "order placed");
    }
}
