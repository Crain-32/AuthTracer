package fixtures.jwtbootauthorities;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Boot's resource server, its authorities set by properties: the roles claim with the ROLE_ prefix, and no scopes.
 */
@SpringBootApplication
@EnableMethodSecurity
@RestController
class JwtBootAuthoritiesApplication {

    private final Reports reports;

    JwtBootAuthoritiesApplication(Reports reports) {
        this.reports = reports;
    }

    @GetMapping("/reports")
    String reports() {
        return reports.daily();
    }

    @GetMapping("/reports/export")
    String export() {
        return reports.export();
    }
}

@Service
class Reports {

    @PreAuthorize("hasRole('ANALYST')")
    String daily() {
        return "daily";
    }

    @PreAuthorize("hasAuthority('SCOPE_reports.export')")
    String export() {
        return "export";
    }
}
