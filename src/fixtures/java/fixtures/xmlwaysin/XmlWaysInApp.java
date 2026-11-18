package fixtures.xmlwaysin;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Configured by WEB-INF/spring/security.xml: the container's login and remember-me.
 */
@RestController
class XmlWaysInEndpoints {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
