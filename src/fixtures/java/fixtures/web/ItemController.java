package fixtures.web;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ItemController {

    @GetMapping("/public/info")
    String info() {
        return "info";
    }

    @GetMapping("/items/{id}")
    String item(@PathVariable long id) {
        return "item";
    }

    @DeleteMapping("/items/{id}")
    void delete(@PathVariable long id) {
    }

    /**
     * Matches {@code /items/**} first, so the later {@code denyAll()} for /items/archive/** never applies.
     */
    @GetMapping("/items/archive/{id}")
    String archived(@PathVariable long id) {
        return "archived";
    }

    @GetMapping("/assets/{name}")
    String asset(@PathVariable String name) {
        return "asset";
    }

    /**
     * Ignored, although /items/** requires a role.
     */
    @GetMapping("/items/feed")
    String feed() {
        return "feed";
    }

    @GetMapping("/beta/feature")
    String beta() {
        return "beta";
    }

    @GetMapping("/audit/log")
    String audit() {
        return "audit";
    }

    @GetMapping("/ops/status")
    String ops() {
        return "ops";
    }

    @GetMapping("/reports/daily")
    String daily() {
        return "daily";
    }

    @GetMapping("/partner/orders")
    String partnerOrders() {
        return "orders";
    }

    /**
     * No rule matches: denied by default.
     */
    @GetMapping("/internal/stats")
    String stats() {
        return "stats";
    }
}
