package fixtures.orders;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Not a bean and never returned from an {@code @AuthorizeReturnObject} method, so the check never runs.
 */
class OrderNote {

    private final String text;

    OrderNote(String text) {
        this.text = text;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public String getText() {
        return text;
    }
}
