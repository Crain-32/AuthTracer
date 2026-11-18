package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * Found by mutationTest: with pre/post method security off, @AuthorizeReturnObject still proxies what a method
 * returns, with the advisors that are on.
 */
class ReturnObjectSecuredFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("returnobjectsecured");

    @Test
    void aReturnedObjectIsProxiedWithTheAdvisorsThatAreOn() {
        assertThat(checks("ingress:GET /iban")).singleElement().satisfies(check ->
                assertThat(check.requirement().authorities()).containsExactly("ROLE_TELLER"));
        // @PreAuthorize has no advisor with pre/post off.
        assertThat(checks("ingress:GET /owner")).isEmpty();
    }

    private List<AuthorizationLocation> checks(String ingress) {
        return path(graph, ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.scope() != AuthorizationLocation.Scope.HTTP_REQUEST).toList();
    }
}
