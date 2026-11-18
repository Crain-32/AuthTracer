package dev.crain.payrollservice.payroll;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

/**
 * The salary changes the next pay run applies, in the order they arrived. In memory.
 */
@Service
public class PayrollLedger {

    private final List<PayrollChange> changes = new CopyOnWriteArrayList<>();

    void record(PayrollChange change) {
        changes.add(change);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Flux<PayrollChange> changes() {
        return Flux.fromIterable(changes);
    }
}
