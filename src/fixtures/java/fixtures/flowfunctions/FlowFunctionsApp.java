package fixtures.flowfunctions;

import java.util.List;
import java.util.function.Function;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

record Account(String owner, String iban) {
}

record Label(String text) {
}

final class Labels {

    private Labels() {
    }

    static Label owner(Account account) {
        return new Label(account.owner());
    }

    static Label iban(Account account) {
        return new Label(account.iban());
    }
}

/**
 * A mapper chosen on a branch: either may be the one applied.
 */
@RestController
class FlowFunctionsController {

    private List<Account> accounts() {
        return List.of(new Account("ada", "DE00"));
    }

    @GetMapping("/labels")
    List<Label> labels(@RequestParam boolean full) {
        Function<Account, Label> mapper = full ? Labels::iban : Labels::owner;
        return accounts().stream().map(mapper).toList();
    }

    /**
     * A lambda over values another function made: it reads what they were made from.
     */
    @GetMapping("/cards")
    List<Card> cards() {
        return accounts().stream().map(Labels::iban).map(label -> new Card(label.text().toUpperCase())).toList();
    }
}

record Card(String title) {
}
