package fixtures.actuatorlegacy;

import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository;
import org.springframework.boot.actuate.web.exchanges.HttpExchangeRepository;
import org.springframework.boot.actuate.web.exchanges.InMemoryHttpExchangeRepository;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.metrics.buffering.BufferingApplicationStartup;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Actuator configured the Boot 2 way (every endpoint off, then each one's enabled flag), at the root of the server,
 * with the repositories auditevents and httpexchanges need and a startup the builder buffers.
 */
@SpringBootApplication
class ActuatorLegacyApp {

    public static void main(String[] args) {
        new SpringApplicationBuilder(ActuatorLegacyApp.class)
                .applicationStartup(new BufferingApplicationStartup(1024)).run(args);
    }

    @Bean
    InMemoryAuditEventRepository auditEvents() {
        return new InMemoryAuditEventRepository();
    }

    @Bean
    HttpExchangeRepository exchanges() {
        return new InMemoryHttpExchangeRepository();
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/health/**").permitAll()
                .anyRequest().hasRole("OPS"));
        return http.build();
    }
}

/**
 * Something with an abstract method, as most applications have.
 */
interface Clock {

    long now();
}
