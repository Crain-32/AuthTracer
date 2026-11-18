package fixtures.webapptype;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Decision 0009: both stacks on the classpath and no security configuration of its own;
 * spring.main.web-application-type=reactive (application.properties) runs it on WebFlux.
 */
@SpringBootApplication
@RestController
class WebAppTypeApplication {

    @GetMapping("/quotes")
    Mono<String> quotes() {
        return Mono.just("quotes");
    }
}
