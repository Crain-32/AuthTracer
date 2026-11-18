package fixtures.jacksonshapes;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonValue;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Properties Jackson finds beyond getX(): a marked method of any name, private fields with visibility ANY; isX() of
 * a boolean only. And types Jackson writes some other way than their properties.
 */
@SpringBootApplication
public class JacksonShapesApp {
}

class AccountView {

    private final String iban = "GB00";

    @JsonProperty("iban")
    public String maskedIban() {
        return "****" + iban.substring(2);
    }

    @JsonGetter("holder")
    String owner() {
        return "ada";
    }

    public boolean isActive() {
        return true;
    }

    // Not a boolean: Jackson doesn't take isX() for it.
    public String isRegion() {
        return "eu";
    }
}

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
class Ledger {

    private String entries = "[]";
    private transient String cache = "";
}

class Token {

    private final String secret = "s";

    @JsonValue
    String value() {
        return secret;
    }
}

class Extra {

    @JsonAnyGetter
    Map<String, Object> rest() {
        return Map.of();
    }
}

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes(@JsonSubTypes.Type(value = Card.class, name = "card"))
abstract class Instrument {
}

class Card extends Instrument {

    public String getPan() {
        return "4111";
    }
}

@RestController
class ShapesController {

    @GetMapping("/account")
    AccountView account() {
        return new AccountView();
    }

    @GetMapping("/ledger")
    Ledger ledger() {
        return new Ledger();
    }

    @GetMapping("/token")
    Token token() {
        return new Token();
    }

    @GetMapping("/extra")
    Extra extra() {
        return new Extra();
    }

    @GetMapping("/instrument")
    Instrument instrument() {
        return new Card();
    }
}
