package fixtures.containers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Response bodies in the containers libraries put around them: a page, a map, HATEOAS models, a concrete list. Each
 * writes the account's fields, under whatever key; one a library's type AuthTracer can't follow.
 */
@SpringBootApplication
@EnableMethodSecurity
public class ContainersApp {
}

class Account {

    private final String owner;
    private final String iban;

    Account(String owner, String iban) {
        this.owner = owner;
        this.iban = iban;
    }

    public String getOwner() {
        return owner;
    }

    public String getIban() {
        return iban;
    }
}

@RestController
@PreAuthorize("hasRole('TELLER')")
class AccountsController {

    private static final Account ACCOUNT = new Account("ada", "GB00");

    @GetMapping("/page")
    Page<Account> page() {
        return new PageImpl<>(List.of(ACCOUNT));
    }

    @GetMapping("/map")
    ResponseEntity<Map<String, Account>> map() {
        return ResponseEntity.ok(Map.of("ada", ACCOUNT));
    }

    @GetMapping("/model")
    EntityModel<Account> model() {
        return EntityModel.of(ACCOUNT);
    }

    @GetMapping("/models")
    CollectionModel<EntityModel<Account>> models() {
        return CollectionModel.of(List.of(EntityModel.of(ACCOUNT)));
    }

    @GetMapping("/list")
    ArrayList<Account> list() {
        return new ArrayList<>(List.of(ACCOUNT));
    }

    @GetMapping("/entry")
    Map.Entry<String, Account> entry() {
        return Map.entry("ada", ACCOUNT);
    }
}
