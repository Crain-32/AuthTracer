package fixtures.actuatorforms;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0041 with EndpointRequest narrowed: changing a logger's level is for operators, reading the endpoints for
 * monitoring, and the links page is left out of that rule.
 */
@SpringBootApplication
class ActuatorFormsApp {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(EndpointRequest.to("loggers").withHttpMethod(HttpMethod.POST)).hasRole("OPS")
                .requestMatchers(EndpointRequest.toAnyEndpoint().excludingLinks()).hasRole("MONITOR")
                .anyRequest().authenticated());
        return http.build();
    }
}
