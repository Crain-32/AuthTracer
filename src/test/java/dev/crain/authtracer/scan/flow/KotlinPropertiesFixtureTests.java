package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.graph.Node;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A Kotlin class's properties as jackson-module-kotlin writes them: a constructor property's annotations are on the
 * constructor's parameter, also when the body declares properties of its own.
 */
class KotlinPropertiesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("kotlinproperties");

    @Test
    void aConstructorPropertyIsNamedByItsParametersAnnotation() {
        assertThat(field("name").jsonName()).isEqualTo("display_name");
        assertThat(field("email").jsonName()).isEqualTo("email");
    }

    @Test
    void theBodysPropertiesAreReadFromTheirFieldOrGetter() {
        assertThat(graph.node("field:fixtures.kotlinproperties.Member.token")).isEmpty();
        assertThat(field("initials").jsonName()).isEqualTo("initials");
        assertThat(graph.nodes(Field.class)).extracting(Node::id).noneMatch(id -> id.contains("KIND"));
    }

    private Field field(String name) {
        return (Field) graph.node("field:fixtures.kotlinproperties.Member." + name).orElseThrow();
    }
}
