package fixtures.transactions;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableMethodSecurity
@EnableTransactionManagement
class TransactionsApp {
}

@RestController
class OrdersController {

    private final OrderService orders;

    OrdersController(OrderService orders) {
        this.orders = orders;
    }

    @PostMapping("/orders/{id}/approve")
    String approve(@PathVariable long id) {
        return orders.approve(id);
    }

    @GetMapping("/orders/{id}")
    String read(@PathVariable long id) {
        return orders.read(id);
    }
}

@Service
class OrderService {

    /**
     * Writes, then checks: the approval is committed before @PostAuthorize decides.
     */
    @Transactional
    @PostAuthorize("returnObject == authentication.name")
    String approve(long id) {
        return "owner";
    }

    @Transactional(readOnly = true)
    @PostAuthorize("returnObject == authentication.name")
    String read(long id) {
        return "owner";
    }
}
