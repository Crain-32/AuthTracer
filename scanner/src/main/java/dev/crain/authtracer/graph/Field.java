package dev.crain.authtracer.graph;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * A property of a type, the unit of field-level AuthZ visibility.
 *
 * @param jsonName the name the field has on the wire, which is how fields are matched across network edges
 * @param javaType the declared type, e.g. {@code java.lang.String} or a nested application type; for a collection
 *        of application objects, an array of them ({@code app.Pet[]} for {@code List<Pet>}); for a map whose values
 *        are application objects, an object of them ({@code app.Pet{}} for {@code Map<String, Pet>}), as JSON
 *        writes it
 * @param labels sensitivity labels from Provided facts, e.g. {@code PII}
 * @param declassified a Provided fact says this field no longer inherits its sources' sensitivity and requirements
 * @param graphQl for a type the GraphQL schema maps: whether the schema has this field (GraphQL never returns one it
 *        doesn't); {@code null} when no schema says (decision 0033)
 * @param views the Jackson {@code @JsonView}s the field is in, empty when it names none
 */
@Supports({Feature.RESPONSE_FIELDS, Feature.APPLICATION_GRAPH})
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record Field(String id, String owner, String name, String jsonName, String javaType, List<String> labels,
        boolean declassified, Boolean graphQl, List<String> views) implements Node {

    public Field {
        labels = labels == null ? List.of() : List.copyOf(labels);
        views = views == null ? List.of() : List.copyOf(views);
    }

    public Field(String id, String owner, String name, String jsonName, String javaType, List<String> labels,
            boolean declassified, Boolean graphQl) {
        this(id, owner, name, jsonName, javaType, labels, declassified, graphQl, List.of());
    }

    /**
     * The type a field's value nests: the element type of an array of application objects ({@code app.Pet} for
     * {@code app.Pet[]}), the value type of a map of them ({@code app.Pet} for {@code app.Pet{}}), else the field's
     * type.
     */
    public static String held(String javaType) {
        return javaType != null && (javaType.endsWith("[]") || isMap(javaType))
                ? javaType.substring(0, javaType.length() - 2) : javaType;
    }

    /**
     * Whether the field holds a map of application objects, written as an object whose values are them: its JSON
     * paths are {@code pets.*.name}.
     */
    public static boolean isMap(String javaType) {
        return javaType != null && javaType.endsWith("{}");
    }

    public static String id(String owner, String name) {
        return "field:" + owner + "." + name;
    }

    /**
     * The owner class of a field id: {@code app.Account} for {@code field:app.Account.iban}.
     */
    public static String ownerOf(String id) {
        return id.substring("field:".length(), id.lastIndexOf('.'));
    }

    /**
     * A field id as people read it, with the owner's simple name: {@code Account.iban}.
     */
    public static String shortName(String id) {
        String owner = ownerOf(id);
        return owner.substring(owner.lastIndexOf('.') + 1) + id.substring(id.lastIndexOf('.'));
    }

    public static Field of(String owner, String name, String jsonName, String javaType) {
        return new Field(id(owner, name), owner, name, jsonName, javaType, List.of(), false, null);
    }

    @Supports(Feature.PROVIDED_FACTS)
    public Field withLabels(List<String> labels) {
        return new Field(id, owner, name, jsonName, javaType, labels, declassified, graphQl, views);
    }

    public Field withGraphQl(boolean inSchema) {
        return new Field(id, owner, name, jsonName, javaType, labels, declassified, inSchema, views);
    }

    public Field withViews(List<String> views) {
        return new Field(id, owner, name, jsonName, javaType, labels, declassified, graphQl, views);
    }

    @Supports(Feature.PROVIDED_FACTS)
    public Field declassify() {
        return new Field(id, owner, name, jsonName, javaType, labels, true, graphQl, views);
    }
}
