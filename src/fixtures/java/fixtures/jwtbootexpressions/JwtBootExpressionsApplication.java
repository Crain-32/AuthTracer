package fixtures.jwtbootexpressions;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Boot's resource server reading authorities with SpEL expressions (Boot 4.1's authorities-claim-expressions), as
 * Keycloak nests them, with the prefix the properties give.
 */
@SpringBootApplication
@RestController
class JwtBootExpressionsApplication {

    @GetMapping("/profile")
    String profile() {
        return "profile";
    }
}
