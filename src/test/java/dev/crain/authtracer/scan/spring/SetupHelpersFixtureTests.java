package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * A factory or expression handler bean set up in an application helper the bean method hands it to, or gets it from,
 * is set up as the bean method would set it.
 */
class SetupHelpersFixtureTests {

    @Test
    void aFactorysPrefixSetInAHelperIsItsPrefix() {
        ApplicationGraph graph = FixtureScans.scan("factoryhelper");
        assertThat(rule(graph, "GET /staff/list").requirement().authorities()).containsExactly("AUTH_STAFF");
    }

    @Test
    void aHandlerMadeInAHelperHasItsPrefix() {
        ApplicationGraph graph = FixtureScans.scan("handlerhelper");
        List<String> authorities = FixtureScans.path(graph, "ingress:GET /reports").stream()
                .flatMap(id -> graph.node(id).stream()).filter(AuthorizationLocation.class::isInstance)
                .map(AuthorizationLocation.class::cast)
                .flatMap(location -> location.requirement().authorities().stream()).toList();
        assertThat(authorities).contains("TEAM_LEAD").doesNotContain("ROLE_LEAD");
    }
}
