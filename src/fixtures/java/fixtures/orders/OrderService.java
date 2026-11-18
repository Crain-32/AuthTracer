package fixtures.orders;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
class OrderService {

    @PreAuthorize("hasAuthority('SCOPE_orders.read')")
    public Order find(long id) {
        return new Order(id, "SKU-" + id);
    }

    @Secured("ROLE_CLERK")
    public Order create(Order order) {
        return order;
    }

    @IsAdmin
    public void delete(long id) {
    }

    /**
     * Calls {@link #audited} on {@code this}, which skips the proxy and therefore the check.
     */
    public String summary(long id) {
        return audited(id);
    }

    @PreAuthorize("hasRole('AUDITOR')")
    public String audited(long id) {
        return "order " + id;
    }

    @RolesAllowed("MANAGER")
    public void approve(long id) {
    }

    @PreAuthorize("hasRole('ADMIN')")
    private void purge() {
    }
}
