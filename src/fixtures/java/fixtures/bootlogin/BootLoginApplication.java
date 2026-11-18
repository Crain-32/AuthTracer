package fixtures.bootlogin;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No SecurityFilterChain bean, and a client registration in the properties: Boot's chain logs users in with OAuth2.
 */
@SpringBootApplication
@RestController
class BootLoginApplication {

    @GetMapping("/profile")
    String profile() {
        return "profile";
    }
}
