package fixtures.webxmlbroken;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0070 (amended): a web.xml with a document type AuthTracer won't read, so its filters are a finding.
 */
@SpringBootApplication
class WebXmlBrokenApp {
}

@RestController
class HomeController {

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
