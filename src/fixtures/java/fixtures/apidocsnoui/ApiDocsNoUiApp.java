package fixtures.apidocsnoui;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0054: the API docs served for clients, the Swagger UI turned off.
 */
@SpringBootApplication
class ApiDocsNoUiApp {
}

@RestController
class HelloController {

    @GetMapping("/hello")
    String hello() {
        return "hello";
    }
}
