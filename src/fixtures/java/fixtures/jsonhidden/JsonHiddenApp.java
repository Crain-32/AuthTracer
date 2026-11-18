package fixtures.jsonhidden;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Properties Jackson doesn't serialize: @JsonIgnore on the field, write-only, and @JsonIgnoreProperties (unless it
 * allows getters).
 */
@JsonIgnoreProperties({ "internalNotes" })
class Account {

    private String username;

    @JsonIgnore
    private String passwordHash;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String pin;

    @JsonProperty("mail")
    private String email;

    private String internalNotes;

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getPin() {
        return pin;
    }

    public String getEmail() {
        return email;
    }

    public String getInternalNotes() {
        return internalNotes;
    }
}

record Card(String last4, @JsonIgnore String cvv) {
}

/**
 * Ignored on read only: {@code allowGetters} still writes the token.
 */
@JsonIgnoreProperties(value = { "token", "token" }, allowGetters = true)
record Session(String user, String token) {
}

@JsonIgnoreProperties({ "serial", "serial" })
record Device(String name, String serial) {
}

@RestController
class AccountController {

    @GetMapping("/account")
    Account account() {
        return new Account();
    }

    @GetMapping("/card")
    Card card() {
        return new Card("4242", "123");
    }

    @GetMapping("/session")
    Session session() {
        return new Session("ada", "t0k3n");
    }

    @GetMapping("/device")
    Device device() {
        return new Device("phone", "SN-1");
    }
}
