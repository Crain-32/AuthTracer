package fixtures.bootopaque;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No SecurityFilterChain bean, and an introspection endpoint in the properties: Boot's resource server chain takes
 * the default's place and introspects every token.
 */
@SpringBootApplication
@RestController
class BootOpaqueApplication {

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
