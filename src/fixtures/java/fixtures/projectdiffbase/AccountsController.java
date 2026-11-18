package fixtures.projectdiffbase;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A service a pull request changes, as of its base: {@code GET /accounts/{id}} for admins only.
 */
@RestController
class AccountsController {

    @GetMapping("/accounts/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    String get(@PathVariable long id) {
        return "account " + id;
    }
}
