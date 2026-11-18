package fixtures.basepath;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class BasePathController {

    @GetMapping("/admin/settings")
    String settings() {
        return "settings";
    }

    @GetMapping("/public/info")
    String info() {
        return "info";
    }

    @GetMapping("/images/logo")
    String logo() {
        return "logo";
    }

    @GetMapping("/home")
    String home() {
        return "home";
    }
}
