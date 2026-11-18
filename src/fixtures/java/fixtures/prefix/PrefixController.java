package fixtures.prefix;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class PrefixController {

    @GetMapping("/dsl")
    String dsl() {
        return "dsl";
    }

    @GetMapping("/factory")
    String factory() {
        return "factory";
    }

    @GetMapping("/expression")
    String expression() {
        return "expression";
    }

    @GetMapping("/pre")
    @PreAuthorize("hasRole('USER')")
    String pre() {
        return "pre";
    }

    @GetMapping("/jsr250")
    @RolesAllowed("AUDITOR")
    String jsr250() {
        return "jsr250";
    }

    @GetMapping("/secured")
    @Secured("ROLE_STAFF")
    String secured() {
        return "secured";
    }
}
