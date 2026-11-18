package fixtures.webstackservlet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0079: Spring MVC and WebFlux are both on the classpath and nothing picks a web application type, so Boot
 * runs it as a Servlet application: the WebFlux chain it declares never runs, and Boot's own Servlet chain does.
 */
@SpringBootApplication
@EnableWebFluxSecurity
public class WebStackServletApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebStackServletApplication.class, args);
    }

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/admin/**").hasRole("ADMIN")
                .anyExchange().permitAll()).build();
    }
}

@RestController
class ReportController {

    @GetMapping("/admin/reports")
    String reports() {
        return "reports";
    }
}
