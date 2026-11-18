package fixtures.gatewaymvcmap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Gateway Server MVC routes keyed by id (application.yml routes-map), behind the servlet chain.
 */
@Configuration
@EnableWebSecurity
class GatewayMvcMapConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/api/payments/**").hasRole("BILLING")
                .anyRequest().authenticated());
        return http.build();
    }
}
