package fixtures.webstackproperty;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0079: the main method asks for a reactive application, but {@code spring.main.web-application-type=servlet}
 * (application.properties) is bound to the application when it runs, after the setter. Only
 * {@code @EnableWebFluxSecurity}, which then secures nothing.
 */
@SpringBootApplication
@EnableWebFluxSecurity
public class WebStackPropertyApplication {

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(WebStackPropertyApplication.class);
        application.setWebApplicationType(WebApplicationType.REACTIVE);
        application.run(args);
    }
}

@RestController
class ReportController {

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
