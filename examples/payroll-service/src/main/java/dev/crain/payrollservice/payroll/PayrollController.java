package dev.crain.payrollservice.payroll;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/payroll")
public class PayrollController {

    private static final Logger log = LoggerFactory.getLogger(PayrollController.class);

    private final PayrollLedger ledger;

    public PayrollController(PayrollLedger ledger) {
        this.ledger = ledger;
    }

    @GetMapping("/changes")
    public Flux<PayrollChange> changes(Principal principal) {
        log.info("GET /payroll/changes by {}", principal.getName());
        return ledger.changes();
    }
}
