package fixtures.customizers;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ThrowingCustomizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class CustomizersSecurityConfig {

    /**
     * Applied to every HttpSecurity before the chain method, so it wins over the chain's permitAll.
     */
    @Bean
    @Order(2)
    Customizer<HttpSecurity> actuator() {
        return http -> http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/**").hasRole("OPS"));
    }

    @Bean
    @Order(1)
    ThrowingCustomizer<HttpSecurity> admin() {
        return http -> http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/shutdown").denyAll()
                .requestMatchers("/admin/**").hasRole("ADMIN"));
    }

    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/**").permitAll()
                        .anyRequest().authenticated())
                .httpBasic(basic -> { });
        return http.build();
    }
}
