package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Egress;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A call out from a lambda body or a closure is named by the method it is written in, so its id doesn't change when
 * the compiler numbers the lambdas differently.
 */
class LambdaCallsFixtureTests {

    @Test
    void aGrpcCallInANestedLambdaIsNamedByItsMethod() {
        ApplicationGraph graph = FixtureScans.scan("lambdacalls");
        String id = "egress:fixtures.lambdacalls.Greeter#greet(java.lang.String) GRPC fixtures.grpcrelay.Relay/Greet";
        assertThat(path(graph, "ingress:GET /greetings/{name}")).contains(id);
        Egress egress = (Egress) graph.node(id).orElseThrow();
        assertThat(egress.callSite().method()).isEqualTo("greet(java.lang.String)");
        assertThat(egress.callSite().line()).isNotNull();
        assertThat(path(graph, "ingress:GET /stock/{sku}")).containsExactly(
                "egress:fixtures.lambdacalls.Stock#count(java.lang.String) GET /stock/{sku}");
    }

    @Test
    void aCallInAKotlinLambdaIsNamedByItsFunction() {
        assertThat(path(FixtureScans.scan("kotlinlambdas"), "ingress:GET /stock/{sku}")).containsExactly(
                "egress:fixtures.kotlinlambdas.KotlinStock#count(java.lang.String) GET /stock/{sku}");
    }

    @Test
    void aCallInAGroovyClosureWithinAClosureIsNamedByItsMethod() {
        assertThat(path(FixtureScans.scan("groovylambdas"), "ingress:GET /stock/{sku}")).containsExactly(
                "egress:fixtures.groovylambdas.GroovyStock#count(java.lang.String) GET /stock/{sku}");
    }
}
