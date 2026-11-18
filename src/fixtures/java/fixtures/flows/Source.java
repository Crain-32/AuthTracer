package fixtures.flows;

import java.math.BigDecimal;

public record Source(String first, String last, BigDecimal amount, String secret) {
}
