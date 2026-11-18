package dev.crain.employeeservice.audit;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private final List<SalaryChange> changes = new CopyOnWriteArrayList<>();
    private final List<CompensationView> views = new CopyOnWriteArrayList<>();

    public void recordSalaryChange(long employeeId, BigDecimal previous, BigDecimal current) {
        changes.add(new SalaryChange(employeeId, previous, current, Instant.now()));
    }

    /**
     * From profile-service's audit events: the viewer is whoever the event names.
     */
    public void recordCompensationView(long employeeId, String viewedBy, Instant at) {
        views.add(new CompensationView(employeeId, viewedBy, at));
    }

    @Secured("ROLE_AUDITOR")
    public List<SalaryChange> history(long employeeId) {
        return changes.stream().filter(change -> change.employeeId() == employeeId).toList();
    }

    @Secured("ROLE_AUDITOR")
    public List<CompensationView> views(long employeeId) {
        return views.stream().filter(view -> view.employeeId() == employeeId).toList();
    }

    public record SalaryChange(long employeeId, BigDecimal previous, BigDecimal current, Instant at) {
    }

    public record CompensationView(long employeeId, String viewedBy, Instant at) {
    }
}
