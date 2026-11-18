package fixtures.flowforms;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

record Account(String owner, int balance, String[] tags, Object note) {
}

/**
 * Values computed from the account's fields, each a different form.
 */
record Figures(int debt, int tagCount, boolean textNote, String firstTag, List<String> names,
        List<String> trimmed) {
}

record Label(String text) {
}

/**
 * A class with a public field, set by its constructor and read directly.
 */
class Point {

    public final String label;

    Point(String label) {
        this.label = label;
    }
}

class Pet {

    public String getName() {
        return "";
    }
}

class BaseView {

    public String getName() {
        return "";
    }
}

/**
 * Inherits name; renamed, ignored and container properties of its own.
 */
@JsonIgnoreProperties("display_name")
class ProfileView extends BaseView {

    @JsonProperty("display_name")
    public String getDisplayName() {
        return "";
    }

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    public String getId() {
        return "";
    }

    @JsonIgnore(false)
    public String getEmail() {
        return "";
    }

    public String[] getTags() {
        return new String[0];
    }

    public Map<String, Pet> getPetsByName() {
        return Map.of();
    }

    public Optional<Pet> getFavourite() {
        return Optional.empty();
    }

    public AtomicReference<Pet> getCurrent() {
        return new AtomicReference<>();
    }
}

/**
 * A builder whose methods read what they set, and whose build takes an argument of its own.
 */
class Statement {

    private final String owner;
    private final String heading;
    private final String period;

    Statement(String owner, String heading, String period) {
        this.owner = owner;
        this.heading = heading;
        this.period = period;
    }

    public String getOwner() {
        return owner;
    }

    public String getHeading() {
        return heading;
    }

    public String getPeriod() {
        return period;
    }

    static StatementBuilder builder() {
        return new StatementBuilder();
    }

    static class StatementBuilder {

        private String owner;
        private String heading;

        StatementBuilder owner(String owner) {
            this.owner = owner;
            this.heading = "Statement for " + this.owner;
            return this;
        }

        Statement build(String period) {
            return new Statement(owner, heading != null ? heading : owner, period);
        }
    }
}

@RestController
class FlowController {

    @GetMapping("/figures")
    Figures figures() {
        Account account = load();
        Object note = account.note();
        Map<String, String> names = new HashMap<>();
        return new Figures(-account.balance(), account.tags().length, note instanceof String, account.tags()[0],
                Arrays.asList(names.getOrDefault("owner", account.owner())),
                Arrays.stream(account.tags()).map(String::trim).toList());
    }

    @GetMapping("/label")
    Label label() {
        Point point = new Point(load().owner());
        return new Label(point.label);
    }

    @GetMapping("/profile")
    ProfileView profile() {
        return new ProfileView();
    }

    @GetMapping("/statement")
    Statement statement() {
        return Statement.builder().owner(load().owner()).build(String.valueOf(load().balance()));
    }

    /**
     * A body a library type wraps: the entity is the response.
     */
    @GetMapping("/entity")
    HttpEntity<Label> entity() {
        return new HttpEntity<>(new Label(load().owner()));
    }

    /**
     * Its generic return type is found by the handler's descriptor, every kind of primitive parameter in it.
     */
    @GetMapping("/converted")
    List<Label> converted(@RequestParam byte b, @RequestParam char c, @RequestParam short s, @RequestParam float f,
            @RequestParam double d) {
        return List.of(new Label(load().owner()));
    }

    /**
     * A generic parameter gives the method a signature, where the array it returns is an array signature.
     */
    @GetMapping("/labels")
    Label[] labels(@RequestParam List<String> names) {
        return new Label[] { new Label(load().owner()) };
    }

    @GetMapping("/mapped")
    Optional<Label> mapped(boolean full) {
        return Optional.of(load()).map(mapper(full));
    }

    private static Function<Account, Label> mapper(boolean full) {
        if (full) {
            return FlowController::full;
        }
        return FlowController::brief;
    }

    private static Label full(Account account) {
        return new Label(account.owner() + " " + account.balance());
    }

    private static Label brief(Account account) {
        return new Label(account.owner());
    }

    private Account load() {
        return new Account("Ada", 10, new String[] { "vip" }, "note");
    }
}
