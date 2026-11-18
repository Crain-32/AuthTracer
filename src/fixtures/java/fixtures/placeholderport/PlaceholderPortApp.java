package fixtures.placeholderport;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Ports the environment may set, with defaults: {@code server.port=${PORT:...}}, as container platforms configure.
 */
@RestController
class StatusController {

    @GetMapping("/status")
    String status() {
        return "up";
    }
}
