package fixtures.feignoauth2;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Decision 0042: with {@code spring.cloud.openfeign.oauth2.enabled}, OpenFeign adds an OAuth2 client token to every
 * client's requests.
 */
@FeignClient("ledger")
interface LedgerClient {

    @GetMapping("/entries/{id}")
    String entry(@PathVariable("id") Long id);
}

@RestController
class LedgerController {

    private final LedgerClient ledger;

    LedgerController(LedgerClient ledger) {
        this.ledger = ledger;
    }

    @GetMapping("/entries/{id}")
    String entry(@PathVariable("id") Long id) {
        return ledger.entry(id);
    }
}
