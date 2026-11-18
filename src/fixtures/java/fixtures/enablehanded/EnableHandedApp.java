package fixtures.enablehanded;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A class without @Configuration is a bean when the application hands it to SpringApplication.run(..).
 */
@SpringBootApplication
public class EnableHandedApp {

    public static void main(String[] args) {
        SpringApplication.run(new Class<?>[] {EnableHandedApp.class, HandedSecurity.class}, args);
    }
}

@EnableMethodSecurity
class HandedSecurity {
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
