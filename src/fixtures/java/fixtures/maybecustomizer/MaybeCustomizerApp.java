package fixtures.maybecustomizer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0111: a customizer's rules come before the chain's, but only under a profile the configuration doesn't
 * activate: the requests they match get them or the chain's rule, whichever asks less.
 */
@SpringBootApplication
public class MaybeCustomizerApp {

    public static void main(String[] args) {
        SpringApplication.run(MaybeCustomizerApp.class, args);
    }
}

@Configuration
class ChainConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().hasRole("STAFF")).build();
    }
}

@Configuration
@Profile("strict")
class StrictRules {

    @Bean
    Customizer<HttpSecurity> adminOnly() {
        return http -> http.authorizeHttpRequests(requests -> requests.requestMatchers("/admin/**").hasRole("ADMIN"));
    }
}

@RestController
class AdminController {

    @GetMapping("/admin/report")
    String report() {
        return "report";
    }
}
