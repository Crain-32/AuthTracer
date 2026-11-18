package fixtures.jsonfields;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

record Account(String owner, String iban, String secret, String note) {
}

/**
 * Fields Jackson writes: public ones (its default visibility) and one {@code @JsonProperty} names; not a transient,
 * an ignored, a private or a static one.
 */
class AccountView {

    public static String VERSION = "1";

    public String owner;

    public transient String cache;

    @JsonIgnore
    public String secret;

    @JsonProperty("iban_number")
    private final String iban;

    private String note;

    AccountView(String iban) {
        this.iban = iban;
    }

    public String getLabel() {
        return "label";
    }
}

@RestController
class JsonFieldsController {

    private Account load() {
        return new Account("ada", "DE00", "pin", "hello");
    }

    @GetMapping("/account")
    AccountView account() {
        Account account = load();
        AccountView view = new AccountView(account.iban());
        view.owner = account.owner();
        view.secret = account.secret();
        view.cache = account.note();
        return view;
    }
}
