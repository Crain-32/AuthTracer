package fixtures.rolebuilder;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class GuestController {

    @GetMapping("/guest/welcome")
    String welcome() {
        return "welcome";
    }
}
