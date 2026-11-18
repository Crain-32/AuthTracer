package fixtures.fields;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.HandleAuthorizationDenied;
import org.springframework.security.authorization.method.NullReturningMethodAuthorizationDeniedHandler;

public class Account {

    private final long id;
    private final String iban;

    public Account(long id, String iban) {
        this.id = id;
        this.iban = iban;
    }

    public long getId() {
        return id;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @HandleAuthorizationDenied(handlerClass = NullReturningMethodAuthorizationDeniedHandler.class)
    public String getIban() {
        return iban;
    }

    /**
     * Not a getter: a method check, which also runs only on the proxy.
     */
    @PreAuthorize("hasRole('TELLER')")
    public void withdraw(long amount) {
    }
}
