package fixtures.groovycalls;

/**
 * A Java bean the Groovy code fills by assigning its properties.
 */
public class Label {

    private String text;

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }
}
