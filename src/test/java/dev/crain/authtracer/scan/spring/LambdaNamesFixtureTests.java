package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Edge;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0089 (amended): what is reached in a lambda is named by the method the lambda is written in, which doesn't
 * change when another lambda is added before it.
 */
class LambdaNamesFixtureTests {

    private static final String LIST = "fixtures.lambdanames.Orders#list(boolean)";

    private final ApplicationGraph graph = FixtureScans.scan("lambdanames");

    @Test
    void aSplitInALambdaIsNamedByItsMethodAndLine() {
        AuthorizationLocation split = (AuthorizationLocation) graph.node(path(graph, "ingress:GET /orders")
                .getLast()).orElseThrow();
        assertThat(split.id()).startsWith("location:SPLIT:" + LIST + ":lambda@");
        assertThat(split.mechanism()).isEqualTo("Branches of a lambda in " + LIST);
        assertThat(split.target().key()).isEqualTo(LIST);
        assertThat(split.id()).endsWith("@" + split.target().line());
    }

    @Test
    void aLambdaCalledWhereItIsWrittenIsNoStepOfItsOwn() {
        assertThat(graph.path("ingress:GET /orders")).extracting(Edge::via)
                .allSatisfy(via -> assertThat(via).noneMatch(method -> method.contains("lambda$")))
                .anySatisfy(via -> assertThat(via).containsExactly(
                        "fixtures.lambdanames.OrdersController#list(boolean)", LIST,
                        "fixtures.lambdanames.Ledger#archived(java.lang.String)"));
    }
}
