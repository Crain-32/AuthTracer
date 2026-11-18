package fixtures.xmlscan.other;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class XmlScannedController {

    @GetMapping("/scanned")
    String scanned() {
        return "scanned";
    }
}
