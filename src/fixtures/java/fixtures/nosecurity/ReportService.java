package fixtures.nosecurity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * No {@code @EnableMethodSecurity} anywhere in this package, so the annotation is decoration only.
 */
@Service
class ReportService {

    @PreAuthorize("hasRole('ADMIN')")
    public String report() {
        return "report";
    }
}
