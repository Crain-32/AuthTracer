package fixtures.fields;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/accounts")
class AccountController {

    private final AccountService accounts;
    private final AccountRepository repository;

    AccountController(AccountService accounts, AccountRepository repository) {
        this.accounts = accounts;
        this.repository = repository;
    }

    /**
     * Returned as is: serializing the proxies calls their checked getters.
     */
    @GetMapping("/all")
    List<Account> all() {
        return accounts.all();
    }

    @GetMapping("/stored/{id}")
    java.util.Optional<Account> stored(@PathVariable long id) {
        return repository.findById(id);
    }

    /**
     * A raw object returned as is: nothing checks its getters.
     */
    @GetMapping("/plain/{id}")
    Account plain(@PathVariable long id) {
        return accounts.raw(id);
    }

    @GetMapping
    List<String> ibans() {
        return accounts.all().stream().map(Account::getIban).toList();
    }

    @GetMapping("/raw/{id}")
    String rawIban(@PathVariable long id) {
        return accounts.raw(id).getIban();
    }

    /**
     * A proxy and a raw object on one path: only the proxy's read is checked.
     */
    @GetMapping("/mixed/{id}")
    String mixed(@PathVariable long id) {
        Account proxied = accounts.all().getFirst();
        Account raw = accounts.raw(id);
        return proxied.getIban() + raw.getIban();
    }

    @GetMapping("/withdraw/{id}")
    String withdraw(@PathVariable long id) {
        accounts.all().getFirst().withdraw(5);
        accounts.raw(id).withdraw(5);
        return "done";
    }

    /**
     * The proxy comes back through a helper method.
     */
    @GetMapping("/first")
    String firstIban() {
        return first().getIban();
    }

    private Account first() {
        return accounts.all().getFirst();
    }

    /**
     * A lambda reads each proxied element.
     */
    @GetMapping("/each")
    List<String> eachIban() {
        List<String> ibans = new java.util.ArrayList<>();
        accounts.all().forEach(account -> ibans.add(account.getIban()));
        return ibans;
    }
}
