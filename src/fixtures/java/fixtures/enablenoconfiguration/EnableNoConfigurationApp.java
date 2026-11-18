package fixtures.enablenoconfiguration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring Security 5's @Enable annotations carried @Configuration; 6's don't. Upgraded as they were, these classes are
 * no beans: method security stays off, and the chain is never made, so Boot's default chain takes the requests.
 */
@SpringBootApplication
public class EnableNoConfigurationApp {

    public static void main(String[] args) {
        SpringApplication.run(EnableNoConfigurationApp.class, args);
    }
}

@EnableMethodSecurity
class MethodSecurityConfig {
}

@EnableWebSecurity
class WebSecurityConfig {

    @Bean
    SecurityFilterChain closed(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().denyAll()).build();
    }
}

@Service
class Vault {

    @PreAuthorize("hasRole('KEEPER')")
    public String open() {
        return "open";
    }
}

@RestController
class VaultController {

    private final Vault vault;

    VaultController(Vault vault) {
        this.vault = vault;
    }

    @GetMapping("/vault")
    String vault() {
        return vault.open();
    }
}
