package fixtures.flows;

import com.fasterxml.jackson.annotation.JsonProperty;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * Written in snake case, but for the name @JsonProperty sets.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record SnakeView(String firstName, String homeURL, @JsonProperty("nick") String nickName) {
}
