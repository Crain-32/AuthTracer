package fixtures.apidocsoff;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0054: springdoc on the classpath, its API docs turned off, as in production.
 */
@SpringBootApplication
class ApiDocsOffApp {
}

@RestController
class HelloController {

    @GetMapping("/hello")
    String hello() {
        return "hello";
    }
}
