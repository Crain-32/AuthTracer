package fixtures.splitpackages.web;

import fixtures.splitpackages.service.Accounts;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication(scanBasePackages = "fixtures.splitpackages")
@EnableMethodSecurity
public class SplitPackagesApp {
}

@RestController
class BalanceController {

    private final Accounts accounts;

    BalanceController(Accounts accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/balance")
    String balance() {
        return accounts.balance();
    }
}
