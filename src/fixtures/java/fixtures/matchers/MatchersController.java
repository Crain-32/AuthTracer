package fixtures.matchers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class MatchersController {

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/reports/{id}")
    String report(@PathVariable long id) {
        return "report";
    }

    @GetMapping("/docs")
    String docs() {
        return "docs";
    }

    @GetMapping("/css/theme")
    String theme() {
        return "theme";
    }

    @GetMapping("/legacy/items")
    String legacyItems() {
        return "items";
    }

    @GetMapping("/expr")
    String expression() {
        return "expr";
    }

    @GetMapping("/expr/bean")
    String expressionBean() {
        return "expr";
    }

    @GetMapping("/ops/status")
    String status() {
        return "ok";
    }

    @GetMapping("/partner/data")
    String partnerData() {
        return "data";
    }

    @PostMapping("/hooks/in")
    void hook() {
    }

    @GetMapping("/hooks/in")
    String hookStatus() {
        return "listening";
    }

    @GetMapping("/old/thing")
    String oldThing() {
        return "old";
    }

    @GetMapping("/new/thing")
    String newThing() {
        return "new";
    }
}
