package fixtures.aspectjlegacy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The legacy annotation in AspectJ mode registers no advisor, so unwoven classes have no check at all.
 */
@SpringBootApplication
public class LegacyWovenApp {

    public static void main(String[] args) {
        SpringApplication.run(LegacyWovenApp.class, args);
    }
}

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, mode = AdviceMode.ASPECTJ)
class LegacyWovenConfig {

    @Bean
    SecurityFilterChain open(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll()).build();
    }
}

@Service
class Ledger {

    @PreAuthorize("hasRole('ACCOUNTANT')")
    public String balance() {
        return "balance";
    }
}

@RestController
class LedgerController {

    private final Ledger ledger;

    LedgerController(Ledger ledger) {
        this.ledger = ledger;
    }

    @GetMapping("/balance")
    String balance() {
        return ledger.balance();
    }
}
