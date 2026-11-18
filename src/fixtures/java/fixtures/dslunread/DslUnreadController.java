package fixtures.dslunread;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DslUnreadController {

    @GetMapping("/internal/report")
    String report() {
        return "report";
    }

    @GetMapping("/users/{id}/orders")
    String orders(@PathVariable String id) {
        return id;
    }

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/public")
    String open() {
        return "open";
    }

    @GetMapping("/api/items")
    String items() {
        return "items";
    }

    @GetMapping("/ops/status")
    String status() {
        return "ok";
    }
}
