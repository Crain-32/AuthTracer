package fixtures.actuatordefault;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Actuator with Spring Boot's own security: health is open, the rest needs a login; only health is exposed.
 */
@SpringBootApplication
class ActuatorDefaultApp {
}

@RestController
class HelloController {

    @GetMapping("/hello")
    String hello() {
        return "hello";
    }
}
