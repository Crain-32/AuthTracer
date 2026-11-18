package fixtures.filters;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class FiltersController {

    @GetMapping("/api/orders")
    String orders() {
        return "orders";
    }

    @DeleteMapping("/api/orders")
    void deleteOrders() {
    }

    @GetMapping("/legacy/report")
    String report() {
        return "report";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
