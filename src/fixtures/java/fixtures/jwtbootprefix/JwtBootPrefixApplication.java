package fixtures.jwtbootprefix;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Boot's resource server, its authority prefix from the environment (application.properties): which authorities a
 * token grants is unknown, so no check is one no token can pass.
 */
@SpringBootApplication
@EnableMethodSecurity
@RestController
class JwtBootPrefixApplication {

    @GetMapping("/teams")
    @PreAuthorize("hasRole('LEAD')")
    String teams() {
        return "teams";
    }
}
