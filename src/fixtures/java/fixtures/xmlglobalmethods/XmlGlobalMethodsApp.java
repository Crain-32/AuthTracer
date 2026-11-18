package fixtures.xmlglobalmethods;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Configured by WEB-INF/spring/security.xml: {@code <global-method-security>} with a {@code <protect-pointcut>}.
 */
@RestController
class XmlGlobalMethodsEndpoints {

    private final Payroll payroll;

    XmlGlobalMethodsEndpoints(Payroll payroll) {
        this.payroll = payroll;
    }

    @PostMapping("/payroll/run")
    String run() {
        return payroll.run();
    }

    @GetMapping("/payroll/preview")
    String preview() {
        return payroll.preview();
    }

    @GetMapping("/payroll/audit")
    String audit() {
        return payroll.audit();
    }
}

@Service
class Payroll {

    public String run() {
        return "ran";
    }

    @PreAuthorize("hasRole('VIEWER')")
    public String preview() {
        return "preview";
    }

    /**
     * {@code secured-annotations} is off, so this annotation is no source and the pointcut decides.
     */
    @Secured("ROLE_AUDIT")
    public String audit() {
        return "audit";
    }
}
