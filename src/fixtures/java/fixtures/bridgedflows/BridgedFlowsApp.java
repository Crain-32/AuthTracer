package fixtures.bridgedflows;

import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

record Account(long id, String owner, String iban) {
}

record AccountView(String owner, String iban) {
}

/**
 * A generic loader: a call on {@code Loader<AccountView>} is {@code Object load(long)}, which the implementation
 * answers with javac's bridge to its {@code AccountView load(long)}.
 */
interface Loader<T> {

    T load(long id);
}

@Component
class AccountLoader implements Loader<AccountView> {

    @Override
    public AccountView load(long id) {
        Account account = find(id);
        return new AccountView(account.owner(), account.iban());
    }

    private Account find(long id) {
        return new Account(id, "Ada", "GB00");
    }
}

@RestController
class AccountController {

    private final Loader<AccountView> accounts;

    AccountController(Loader<AccountView> accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/accounts/{id}")
    AccountView account(@PathVariable long id) {
        return accounts.load(id);
    }
}
