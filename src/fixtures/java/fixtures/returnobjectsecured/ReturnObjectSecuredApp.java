package fixtures.returnobjectsecured;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Pre/post method security off, @Secured on: @AuthorizeReturnObject still proxies the account (7.1.1 imports
 * AuthorizationProxyConfiguration whatever the flags say), with the @Secured advisor, and without the pre/post ones.
 */
@SpringBootApplication
@EnableMethodSecurity(prePostEnabled = false, securedEnabled = true)
public class ReturnObjectSecuredApp {
}

class Account {

    @Secured("ROLE_TELLER")
    public String getIban() {
        return "GB00";
    }

    @PreAuthorize("hasRole('AUDITOR')")
    public String getOwner() {
        return "ada";
    }
}

@Service
class Accounts {

    @AuthorizeReturnObject
    public Account find() {
        return new Account();
    }
}

@RestController
class AccountController {

    private final Accounts accounts;

    AccountController(Accounts accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/iban")
    String iban() {
        return accounts.find().getIban();
    }

    @GetMapping("/owner")
    String owner() {
        return accounts.find().getOwner();
    }
}
