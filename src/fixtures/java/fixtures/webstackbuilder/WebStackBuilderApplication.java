package fixtures.webstackbuilder;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Decision 0079: the application builder makes it a reactive application.
 */
@SpringBootApplication
@EnableWebFluxSecurity
public class WebStackBuilderApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(WebStackBuilderApplication.class).web(WebApplicationType.REACTIVE).run(args);
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().hasRole("STAFF")).build();
    }
}

@RestController
class ReportController {

    @GetMapping("/reports")
    Mono<String> reports() {
        return Mono.just("reports");
    }
}
