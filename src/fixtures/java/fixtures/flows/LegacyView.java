package fixtures.flows;

/**
 * A class (not a record): its properties come from getters, its values from the constructor.
 */
public class LegacyView {

    private final String name;

    public LegacyView(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
