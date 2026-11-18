package fixtures.flows;

/**
 * Built with a fluent builder, as Lombok's @Builder writes one.
 */
public class OrderDto {

    private final String customer;
    private final String secret;

    OrderDto(String customer, String secret) {
        this.customer = customer;
        this.secret = secret;
    }

    public static OrderDtoBuilder builder() {
        return new OrderDtoBuilder();
    }

    public String getCustomer() {
        return customer;
    }

    public String getSecret() {
        return secret;
    }

    public static class OrderDtoBuilder {

        private String customer;
        private String secret;

        OrderDtoBuilder() {
        }

        public OrderDtoBuilder customer(String customer) {
            this.customer = customer;
            return this;
        }

        public OrderDtoBuilder secret(String secret) {
            this.secret = secret;
            return this;
        }

        public OrderDto build() {
            return new OrderDto(this.customer, this.secret);
        }
    }
}
