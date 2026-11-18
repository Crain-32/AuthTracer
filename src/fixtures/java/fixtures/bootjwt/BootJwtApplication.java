package fixtures.bootjwt;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No SecurityFilterChain bean, and an issuer in the properties: Boot's resource server chain takes the default's place.
 */
@SpringBootApplication
@RestController
class BootJwtApplication {

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
