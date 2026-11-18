package fixtures.builderstatements;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

record Order(String customer, String card, int total) {
}

/**
 * Built with a hand-written nested {@code Builder}, its calls made one statement at a time.
 */
class Receipt {

    private final String customer;
    private final String card;
    private final int total;

    private Receipt(String customer, String card, int total) {
        this.customer = customer;
        this.card = card;
        this.total = total;
    }

    static Builder builder() {
        return new Builder();
    }

    public String getCustomer() {
        return customer;
    }

    public String getCard() {
        return card;
    }

    public int getTotal() {
        return total;
    }

    static final class Builder {

        private String customer;
        private String card;
        private int total;

        Builder customer(String customer) {
            this.customer = customer;
            return this;
        }

        Builder card(String card) {
            this.card = card;
            return this;
        }

        Builder total(int total) {
            this.total = total;
            return this;
        }

        Receipt build() {
            return new Receipt(customer, card, total);
        }
    }
}

@RestController
class ReceiptController {

    @GetMapping("/receipt")
    Receipt receipt() {
        Order order = load();
        Receipt.Builder builder = Receipt.builder();
        builder.customer(order.customer());
        builder.card(order.card());
        builder.total(order.total());
        return builder.build();
    }

    private Order load() {
        return new Order("Ada", "4111", 42);
    }
}
