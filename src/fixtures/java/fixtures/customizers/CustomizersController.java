package fixtures.customizers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CustomizersController {

    @GetMapping("/actuator/health")
    String health() {
        return "up";
    }

    @PostMapping("/actuator/shutdown")
    void shutdown() {
    }

    @GetMapping("/admin/users")
    String users() {
        return "users";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
