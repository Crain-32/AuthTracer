package fixtures.jacksonnamespreferred;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Jackson 3 is on the classpath, but the application asks Spring Boot for Jackson 2's converter
 * (spring.http.converters.preferred-json-mapper=jackson2).
 */
class Badge {

    public String getSSN() {
        return "123";
    }
}

@RestController
class BadgeController {

    @GetMapping("/badge")
    Badge badge() {
        return new Badge();
    }
}
