package fixtures.actuator;

import java.util.List;

import org.springframework.boot.actuate.endpoint.Access;
import org.springframework.boot.actuate.endpoint.annotation.DeleteOperation;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.boot.actuate.endpoint.annotation.Selector;
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.boot.health.actuate.endpoint.HealthEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

/**
 * Actuator: exposed endpoints, a read-only one, and the application's own endpoint.
 */
@SpringBootApplication
class ActuatorApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(EndpointRequest.to(HealthEndpoint.class)).permitAll()
                .requestMatchers(EndpointRequest.toAnyEndpoint().excluding("heapdump")).hasRole("OPS")
                .anyRequest().authenticated());
        return http.build();
    }
}

record AuditRecord(String id, String user, String action) {
}

@Component
@Endpoint(id = "audit")
class AuditEndpoint {

    @ReadOperation
    List<AuditRecord> records() {
        return List.of();
    }

    @ReadOperation
    AuditRecord record(@Selector String id) {
        return new AuditRecord(id, "ann", "login");
    }

    @DeleteOperation
    void clear() {
    }
}

/**
 * Read-only unless configured otherwise: its write operation isn't mapped.
 */
@Component
@Endpoint(id = "ops", defaultAccess = Access.READ_ONLY)
class OpsEndpoint {

    @ReadOperation
    String status() {
        return "ok";
    }

    @WriteOperation
    void restart() {
    }
}
