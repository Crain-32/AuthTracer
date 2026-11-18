package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Decision 0032: Spring gRPC's not(), access(..) and fullyAuthenticated().
 */
class GrpcFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("grpcforms");

    @Test
    void aNegatedRuleIsTheNegationOfItsRequirement() {
        Requirement ping = rule(graph, "GRPC fixtures.grpc.Greeter/Ping").requirement();
        assertThat(ping.kind()).isEqualTo(Kind.NOT);
        assertThat(ping.operands()).singleElement().satisfies(operand ->
                assertThat(operand.authorities()).containsExactly("ROLE_SUSPENDED"));
    }

    @Test
    void aManagerPassedToAccessIsItsRequirement() {
        assertThat(rule(graph, "GRPC fixtures.grpc.Greeter/list_greetings").requirement().authorities())
                .containsExactly("ROLE_LISTER");
        assertThat(rule(graph, "GRPC fixtures.grpc.Greeter/SayHello").requirement().kind())
                .isEqualTo(Kind.FULLY_AUTHENTICATED);
    }
}
