package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

/**
 * HTTP-15 on Boot's default chain: a customizer rule whose patterns the environment names may match before the
 * rules after it, and before Boot's own anyRequest().authenticated().
 */
class CustomizerFormsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("customizerforms");

    @Test
    void aCustomizerRuleThatMayMatchComesBeforeTheNextCustomizers() {
        AuthorizationLocation admin = rule(graph, "GET /admin/users");
        assertThat(admin.id()).startsWith("location:SPLIT:");
        assertThat(admin.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.PERMIT_ALL, Kind.ANY_AUTHORITY);
    }

    @Test
    void andBeforeBootsDefault() {
        AuthorizationLocation home = rule(graph, "GET /home");
        assertThat(home.requirement().operands()).extracting(Requirement::kind)
                .containsExactly(Kind.PERMIT_ALL, Kind.AUTHENTICATED);
        assertThat(home.routePattern()).endsWith(" or anyRequest");
    }
}
