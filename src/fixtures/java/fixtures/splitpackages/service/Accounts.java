package fixtures.splitpackages.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * The service layer, in a package of its own: scanned with only the web package, its check is a library's.
 */
@Service
public class Accounts {

    @PreAuthorize("hasRole('TELLER')")
    public String balance() {
        return "0";
    }
}
