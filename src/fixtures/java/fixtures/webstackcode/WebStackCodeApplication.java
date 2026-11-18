package fixtures.webstackcode;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Decision 0079: the main method makes it a reactive application, so its WebFlux chain runs and the Servlet chain
 * left over from before never does.
 */
@SpringBootApplication
@EnableWebFluxSecurity
public class WebStackCodeApplication {

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(WebStackCodeApplication.class);
        application.setWebApplicationType(WebApplicationType.REACTIVE);
        application.run(args);
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/admin/**").hasRole("ADMIN")
                .anyExchange().authenticated()).build();
    }

    @Bean
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
    }
}

@RestController
class ReportController {

    @GetMapping("/admin/reports")
    Mono<String> reports() {
        return Mono.just("reports");
    }
}
