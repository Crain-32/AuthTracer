package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.graph.Payload;
import org.junit.jupiter.api.Test;

/**
 * A generic response body named by a {@code ParameterizedTypeReference}: its type is the anonymous subclass's
 * generic superclass, as the class file's signature has it.
 */
class TypedBodiesFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("typedbodies");

    @Test
    void aParameterizedTypeReferenceNamesTheBody() {
        assertThat(graph.nodes(Egress.class)).singleElement()
                .satisfies(egress -> assertThat(egress.response())
                        .isEqualTo(new Payload("fixtures.typedbodies.Employee", true)));
    }
}
