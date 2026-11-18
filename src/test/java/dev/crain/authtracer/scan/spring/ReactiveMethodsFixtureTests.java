package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.path;
import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Finding;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class ReactiveMethodsFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("webfluxmethods");

    @Test
    void prePostTakesThePrefixButNotTheHierarchy() {
        assertThat(check(graph, "GET /staff", "@PreAuthorize").requirement().authorities()).containsExactly("GRP_STAFF");
        assertThat(check(graph, "GET /me", "@PostAuthorize").phase()).isEqualTo(AuthorizationLocation.Phase.POST);
    }

    @Test
    void securedNeverRunsUnderReactiveMethodSecurity() {
        assertThat(graph.findings()).filteredOn(finding -> finding.kind() == Finding.Kind.NOT_ENFORCED)
                .extracting(Finding::message).anySatisfy(message -> assertThat(message)
                        .contains("@Secured", "@EnableReactiveMethodSecurity only handles"));
    }

    @Test
    void reactivePointcutAdvisors() {
        AuthorizationLocation ledger = check(graph, "GET /balance", "Advisor guardLedger()");
        assertThat(ledger.requirement().authorities()).containsExactly("ROLE_BOOKKEEPER");
    }

    @Test
    void anExpressionHandlerBeanBringsTheHierarchy() {
        ApplicationGraph handler = FixtureScans.scan("webfluxhandler");
        assertThat(check(handler, "GET /rota", "@PreAuthorize").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_STAFF", "ROLE_ADMIN");
        assertThat(rule(handler, "GET /rota").mechanism()).isEqualTo("Spring Security default SecurityWebFilterChain");
    }


    private static AuthorizationLocation check(ApplicationGraph graph, String ingress, String mechanism) {
        return path(graph, "ingress:" + ingress).stream().map(id -> graph.node(id).orElseThrow())
                .filter(AuthorizationLocation.class::isInstance).map(AuthorizationLocation.class::cast)
                .filter(location -> location.mechanism().equals(mechanism)).findFirst().orElseThrow();
    }
}
