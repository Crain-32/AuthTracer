package fixtures.lambdanames;

import java.util.List;
import java.util.stream.Stream;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0089 (amended): checks reached in lambdas, one of which branches, are named by the methods the lambdas
 * are written in.
 */
@Configuration
@EnableMethodSecurity
class LambdaNamesConfig {
}

@RestController
class OrdersController {

    private final Orders orders;

    OrdersController(Orders orders) {
        this.orders = orders;
    }

    @GetMapping("/orders")
    List<String> list(@RequestParam boolean archived) {
        return orders.list(archived);
    }
}

@Service
class Orders {

    private final Ledger ledger;

    Orders(Ledger ledger) {
        this.ledger = ledger;
    }

    List<String> list(boolean archived) {
        return Stream.of("first", "second").map(id -> {
            if (archived) {
                return ledger.archived(id);
            }
            return ledger.current(id);
        }).toList();
    }
}

@Service
class Ledger {

    @PreAuthorize("hasRole('ARCHIVIST')")
    public String archived(String id) {
        return id;
    }

    @PreAuthorize("hasRole('CLERK')")
    public String current(String id) {
        return id;
    }
}
