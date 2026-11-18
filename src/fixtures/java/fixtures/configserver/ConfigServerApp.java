package fixtures.configserver;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.config.server.EnableConfigServer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Decision 0055: a config server under /config whose chain leaves /decrypt open.
 */
@SpringBootApplication
@EnableConfigServer
class ConfigServerApp {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/config/decrypt").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}
