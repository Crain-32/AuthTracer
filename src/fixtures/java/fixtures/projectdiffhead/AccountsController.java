package fixtures.projectdiffhead;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code projectdiffbase} after the pull request: {@code GET /accounts/{id}} for anyone signed in, weaker than before.
 */
@RestController
class AccountsController {

    @GetMapping("/accounts/{id}")
    @PreAuthorize("isAuthenticated()")
    String get(@PathVariable long id) {
        return "account " + id;
    }
}
