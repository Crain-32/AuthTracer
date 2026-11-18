package fixtures.fields;

import java.math.BigDecimal;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Two checked getters, declared out of name order.
 */
public class Statement {

    private final BigDecimal total;
    private final BigDecimal balance;

    public Statement(BigDecimal total, BigDecimal balance) {
        this.total = total;
        this.balance = balance;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public BigDecimal getTotal() {
        return total;
    }

    @PreAuthorize("hasRole('TELLER')")
    public BigDecimal getBalance() {
        return balance;
    }
}
