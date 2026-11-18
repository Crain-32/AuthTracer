package fixtures.fields;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Only ever proxied through {@code AuthorizationProxyFactory}.
 */
public class Card {

    private final String number;

    public Card(String number) {
        this.number = number;
    }

    @PreAuthorize("hasAuthority('cards:read')")
    public String getNumber() {
        return number;
    }
}
