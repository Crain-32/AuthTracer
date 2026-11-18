package fixtures.libraryfactories;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A chain built from Spring's HttpSecurity, to which every AbstractHttpConfigurer in a library jar's
 * META-INF/spring.factories is applied first.
 */
@SpringBootApplication
class LibraryFactoriesApp {
}

@Configuration
@EnableWebSecurity
class LibraryFactoriesChain {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .httpBasic(basic -> { })
                .build();
    }
}

@RestController
class LedgerController {

    @GetMapping("/ledger")
    String ledger() {
        return "ledger";
    }
}
