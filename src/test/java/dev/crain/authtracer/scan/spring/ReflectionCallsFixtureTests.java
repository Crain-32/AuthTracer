package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.graph.Opaque;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A constructor or a method handle called reflectively is an opaque step of the call path, reported; asking a
 * Constructor or a MethodHandle about itself is not a call.
 */
class ReflectionCallsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("reflectioncalls");

    @Test
    void aConstructorCalledByReflectionIsOpaque() {
        assertThat(path(graph, "ingress:GET /plugins/{name}")).singleElement().satisfies(id ->
                assertThat(graph.node(id)).get().isInstanceOfSatisfying(Opaque.class, opaque ->
                        assertThat(opaque.reason()).isEqualTo("Reflection (Constructor.newInstance)")));
    }

    @Test
    void aMethodHandleInvokedIsOpaque() {
        assertThat(path(graph, "ingress:GET /tasks/{task}")).singleElement().satisfies(id ->
                assertThat(graph.node(id)).get().isInstanceOfSatisfying(Opaque.class, opaque ->
                        assertThat(opaque.reason()).isEqualTo("Method handle (MethodHandle.invoke)")));
    }

    @Test
    void eachIsReportedOnce() {
        assertThat(messages()).hasSize(2)
                .anySatisfy(message -> assertThat(message).startsWith("On GET /plugins/{name}: Reflection"
                        + " (Constructor.newInstance)"))
                .anySatisfy(message -> assertThat(message).startsWith("On GET /tasks/{task}: Method handle"
                        + " (MethodHandle.invoke)"));
    }

    private List<String> messages() {
        return graph.findings().stream().filter(finding -> finding.kind() == Finding.Kind.OPAQUE_CALLPATH)
                .map(Finding::message).toList();
    }
}
