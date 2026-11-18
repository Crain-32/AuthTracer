package fixtures.roles;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class RolesController {

    @GetMapping("/staff/rota")
    String rota() {
        return "rota";
    }

    /**
     * Its own expression handler: the hierarchy doesn't apply.
     */
    @GetMapping("/legacy/page")
    String legacy() {
        return "legacy";
    }

    @GetMapping("/both/report")
    String both() {
        return "report";
    }

    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasAuthority('profile:read')")
    String profile() {
        return "profile";
    }

    @GetMapping("/admin")
    @Secured("ROLE_ADMIN")
    String admin() {
        return "admin";
    }
}
