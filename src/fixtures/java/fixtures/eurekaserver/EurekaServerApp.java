package fixtures.eurekaserver;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0057: a Eureka server whose chain lets anyone register.
 */
@SpringBootApplication
@EnableEurekaServer
class EurekaServerApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/eureka/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}
