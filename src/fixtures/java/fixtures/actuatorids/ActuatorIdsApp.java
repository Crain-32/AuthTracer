package fixtures.actuatorids;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint ids written as Boot compares them, in camel case or with dashes (thread-dump, configProps, an excluded
 * scheduled-tasks), a path mapping keyed threadDump, and the health endpoint served at a group's additional path and
 * the probes' paths too, which Boot's own chain lets everyone reach.
 */
@SpringBootApplication
class ActuatorIdsApp {
}

@RestController
class HelloController {

    @GetMapping("/hello")
    String hello() {
        return "hello";
    }
}
