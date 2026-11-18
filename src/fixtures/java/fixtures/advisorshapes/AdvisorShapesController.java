package fixtures.advisorshapes;

import java.util.List;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AdvisorShapesController {

    private final Payroll payroll;
    private final Vault vault;

    AdvisorShapesController(Payroll payroll, Vault vault) {
        this.payroll = payroll;
        this.vault = vault;
    }

    @GetMapping("/payroll")
    List<String> payslips() {
        return payroll.payslips();
    }

    @PostMapping("/payroll/timesheets")
    void submit(@RequestBody List<String> timesheets) {
        payroll.submit(timesheets);
    }

    @PostMapping("/payroll/approve")
    void approve() {
        payroll.approve();
    }

    @GetMapping("/payroll/report")
    String report() {
        return payroll.report();
    }

    @GetMapping("/payroll/audit")
    String audit() {
        return payroll.audit();
    }

    @GetMapping("/payroll/archive")
    String archive() {
        return payroll.archive();
    }

    @GetMapping("/payroll/holidays")
    String holidays() {
        return payroll.holidays();
    }

    @GetMapping("/vault/any-role")
    String anyRole() {
        return vault.anyRole();
    }

    @GetMapping("/vault/prefixed-role")
    String prefixedRole() {
        return vault.prefixedRole();
    }

    @GetMapping("/vault/all-roles")
    String allRoles() {
        return vault.allRoles();
    }

    @GetMapping("/vault/prefixed-authorities")
    String prefixedAuthorities() {
        return vault.prefixedAuthorities();
    }

    @GetMapping("/vault/all-authorities")
    String allAuthorities() {
        return vault.allAuthorities();
    }

    @GetMapping("/vault/any-authority")
    String anyAuthority() {
        return vault.anyAuthority();
    }

    @GetMapping("/vault/signed-in")
    String signedIn() {
        return vault.signedIn();
    }

    @GetMapping("/vault/fully")
    String fully() {
        return vault.fully();
    }

    @GetMapping("/vault/remembered")
    String remembered() {
        return vault.remembered();
    }

    @GetMapping("/vault/anonymous")
    String anonymous() {
        return vault.anonymous();
    }

    @GetMapping("/vault/open")
    String open() {
        return vault.open();
    }

    @GetMapping("/vault/closed")
    String closed() {
        return vault.closed();
    }

    @GetMapping("/vault/composed")
    String composed() {
        return vault.composed();
    }

    @GetMapping("/vault/configured")
    String configured() {
        return vault.configured();
    }
}

@Service
class Payroll {

    @PostFilter("filterObject.endsWith(authentication.name)")
    List<String> payslips() {
        return List.of();
    }

    @PreFilter("filterObject.startsWith(authentication.name)")
    void submit(List<String> timesheets) {
    }

    @PreAuthorize("hasRole('MANAGER')")
    @Secured("ROLE_CLERK")
    void approve() {
    }

    @PostAuthorize("returnObject != null")
    String report() {
        return "report";
    }

    @RolesAllowed("AUDITOR")
    String audit() {
        return "audit";
    }

    @DenyAll
    String archive() {
        return "archive";
    }

    @PermitAll
    String holidays() {
        return "holidays";
    }
}

/**
 * One method per manager its pointcut advisor is built with.
 */
@Service
class Vault {

    String anyRole() {
        return "vault";
    }

    String prefixedRole() {
        return "vault";
    }

    String allRoles() {
        return "vault";
    }

    String prefixedAuthorities() {
        return "vault";
    }

    String allAuthorities() {
        return "vault";
    }

    String anyAuthority() {
        return "vault";
    }

    String signedIn() {
        return "vault";
    }

    String fully() {
        return "vault";
    }

    String remembered() {
        return "vault";
    }

    String anonymous() {
        return "vault";
    }

    String open() {
        return "vault";
    }

    String closed() {
        return "vault";
    }

    String composed() {
        return "vault";
    }

    String configured() {
        return "vault";
    }
}
