package fixtures.webstackchains;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A Servlet application (its properties say so) with a WebFlux chain, which never runs: Boot's default Servlet chain
 * logs in with a form or HTTP Basic, not with the chain's JWTs.
 */
@SpringBootApplication
@RestController
class WebStackChainsApplication {

    @Bean
    SecurityWebFilterChain api(ServerHttpSecurity http) {
        http.authorizeExchange(exchange -> exchange.anyExchange().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @GetMapping("/reports")
    String reports() {
        return "reports";
    }
}
