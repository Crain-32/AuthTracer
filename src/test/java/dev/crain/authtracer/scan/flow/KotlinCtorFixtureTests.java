package dev.crain.authtracer.scan.flow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Field;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A Kotlin primary constructor with parameters that aren't properties: each parameter's annotations go to the
 * property of its name, as jackson-module-kotlin links them.
 */
class KotlinCtorFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("kotlinctor");

    @Test
    void aConstructorPropertyKeepsItsAnnotationsPastAPlainParameter() {
        assertThat(field("holder").jsonName()).isEqualTo("account_holder");
        assertThat(graph.node("field:fixtures.kotlinctor.Account.pin")).isEmpty();
        assertThat(field("masked").jsonName()).isEqualTo("masked");
    }

    @Test
    void aPlainParametersAnnotationsGoToTheBodysPropertyOfItsName() {
        assertThat(field("code").jsonName()).isEqualTo("short_code");
    }

    private Field field(String name) {
        return (Field) graph.node("field:fixtures.kotlinctor.Account." + name).orElseThrow();
    }
}
