package fixtures.customizerboot;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * No SecurityFilterChain bean: Boot's default chain gets the customizer's rules first.
 */
@SpringBootApplication
@RestController
class BootApplication {

    @Bean
    Customizer<HttpSecurity> publicDocs() {
        return http -> http.authorizeHttpRequests(authorize -> authorize.requestMatchers("/docs/**").permitAll());
    }

    @GetMapping("/docs/index")
    String docs() {
        return "docs";
    }

    @GetMapping("/data")
    String data() {
        return "data";
    }
}
