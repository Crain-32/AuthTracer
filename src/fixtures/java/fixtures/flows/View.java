package fixtures.flows;

import java.math.BigDecimal;

import com.fasterxml.jackson.annotation.JsonProperty;

public record View(
        String direct,
        @JsonProperty("display_name") String concatenated,
        Nested complex,
        String band,
        String passedThrough,
        int secretLength) {

    static View of(Source source) {
        return new View(
                source.first(),
                source.first() + " " + source.last(),
                new Nested(source.first()),
                band(source.amount()),
                Helpers.same(source.secret()),
                source.secret().length());
    }

    /**
     * Returns constants only, but which one depends on the amount: an implicit flow.
     */
    static String band(BigDecimal amount) {
        if (amount.compareTo(BigDecimal.TEN) > 0) {
            return "HIGH";
        }
        return "LOW";
    }
}
