package fixtures.templates;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class TemplatesController {

    @GetMapping("/admin")
    @HasRole("ADMIN")
    String admin() {
        return "admin";
    }

    @GetMapping("/reports")
    @HasAnyScope({ "'SCOPE_reports.read'", "'SCOPE_reports.admin'" })
    String reports() {
        return "reports";
    }

    @GetMapping("/tenant")
    @TenantAccess
    String tenant() {
        return "tenant";
    }

    @GetMapping("/other-tenant")
    @TenantAccess(tenant = "globex")
    String otherTenant() {
        return "other";
    }
}
