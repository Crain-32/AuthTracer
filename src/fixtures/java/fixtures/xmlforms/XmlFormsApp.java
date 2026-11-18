package fixtures.xmlforms;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Configured by WEB-INF/spring/security.xml: a chain matched with regular expressions, one with no intercept-url, and
 * one for the rest.
 */
@RestController
class XmlFormsEndpoints {

    @GetMapping("/legacy/reports/{id}")
    String report(@PathVariable long id) {
        return "report";
    }

    @GetMapping("/legacy/home")
    String legacyHome() {
        return "home";
    }

    @PostMapping("/hooks/github")
    void github() {
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
