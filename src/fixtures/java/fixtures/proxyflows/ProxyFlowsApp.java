package fixtures.proxyflows;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.repository.Repository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0014: the ways an authorization proxy travels before its checked getter is called: passed to another
 * bean, to a bound method reference, captured by a lambda, out of a proxied array, inside an Optional, from a
 * repository method, and from the proxy factory through a cast.
 */
@Configuration
@EnableMethodSecurity
class ProxyFlowsConfig {
}

class Account {

    private final String iban;

    Account(String iban) {
        this.iban = iban;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public String getIban() {
        return iban;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public boolean isFrozen() {
        return false;
    }
}

/**
 * A Spring Data repository whose one method returns a proxy.
 */
interface AccountRepository extends Repository<Account, Long> {

    @AuthorizeReturnObject
    Optional<Account> findByIban(String iban);
}

class Card {

    private final String number;

    Card(String number) {
        this.number = number;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public String getNumber() {
        return number;
    }
}

@Component
class CardStore {

    public Iterable<Card> all() {
        return List.of(new Card("4111"));
    }
}

@Service
class AccountService {

    @AuthorizeReturnObject
    public List<Account> all() {
        return List.of(new Account("DE00 1234"));
    }

    @AuthorizeReturnObject
    public Account[] array() {
        return new Account[] {new Account("DE00 1234")};
    }
}

@Component
class Statements {

    public String describe(Account account) {
        return "IBAN " + account.getIban();
    }
}

@RestController
@RequestMapping("/accounts")
class AccountController {

    private final AccountService accounts;
    private final Statements statements;
    private final AccountRepository repository;

    AccountController(AccountService accounts, Statements statements, AccountRepository repository) {
        this.accounts = accounts;
        this.statements = statements;
        this.repository = repository;
    }

    @GetMapping("/passed")
    String passed() {
        return statements.describe(accounts.all().getFirst());
    }

    @GetMapping("/bound")
    List<String> bound() {
        return accounts.all().stream().map(statements::describe).toList();
    }

    @GetMapping("/captured")
    String captured() {
        Account first = accounts.all().getFirst();
        Supplier<String> iban = () -> first.getIban();
        return iban.get();
    }

    @GetMapping("/array")
    String array() {
        return accounts.array()[0].getIban();
    }

    @GetMapping("/optional")
    String optional() {
        return Optional.of(accounts.all().getFirst()).map(Account::getIban).orElse("");
    }

    @GetMapping("/frozen")
    boolean frozen() {
        return accounts.all().getFirst().isFrozen();
    }

    @GetMapping("/by-iban")
    String byIban(@RequestParam String iban) {
        return repository.findByIban(iban).map(Account::getIban).orElse("");
    }
}

@RestController
class CardController {

    private final CardStore cards;
    private final AuthorizationProxyFactory proxyFactory;

    CardController(CardStore cards, AuthorizationProxyFactory proxyFactory) {
        this.cards = cards;
        this.proxyFactory = proxyFactory;
    }

    /**
     * The proxied collection's elements are the type the call that produced it returns, through the cast.
     */
    @GetMapping("/cards")
    @SuppressWarnings("unchecked")
    List<String> numbers() {
        Iterable<Card> found = cards.all();
        Collection<Card> owned = (Collection<Card>) found;
        Collection<Card> proxied = (Collection<Card>) proxyFactory.proxy(owned);
        return proxied.stream().map(Card::getNumber).toList();
    }
}
