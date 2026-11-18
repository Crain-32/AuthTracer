package fixtures.actuatorgateway;

import java.util.Map;

import org.springframework.boot.actuate.endpoint.web.annotation.RestControllerEndpoint;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * A reactive Spring Cloud Gateway with its actuator endpoint exposed read-only, and an endpoint of the application's
 * written as controller mappings, some inherited from a base class.
 */
@SpringBootApplication
@EnableWebFluxSecurity
class ActuatorGatewayApp {

    @Bean
    SecurityWebFilterChain chain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.pathMatchers("/actuator/**").hasRole("OPS")
                .anyExchange().authenticated()).build();
    }
}

record Toggle(String name, boolean on) {
}

abstract class ToggleEndpointSupport {

    @GetMapping("/{name}")
    public Toggle toggle(@PathVariable String name) {
        return new Toggle(name, false);
    }

    @GetMapping("/count")
    public int count() {
        return 0;
    }
}

@Component
@SuppressWarnings("removal")
@RestControllerEndpoint(id = "toggles")
class TogglesEndpoint extends ToggleEndpointSupport {

    @Override
    @GetMapping("/{name}")
    public Toggle toggle(@PathVariable String name) {
        return new Toggle(name, true);
    }

    @PostMapping("/{name}")
    public Toggle flip(@PathVariable String name) {
        return new Toggle(name, true);
    }

    /**
     * Any method: Actuator maps it as a read.
     */
    @RequestMapping("/export")
    public Map<String, Boolean> export() {
        return Map.of();
    }
}
