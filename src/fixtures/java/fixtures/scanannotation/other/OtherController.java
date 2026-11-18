package fixtures.scanannotation.other;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class OtherController {

    @GetMapping("/other")
    String other() {
        return "other";
    }
}
