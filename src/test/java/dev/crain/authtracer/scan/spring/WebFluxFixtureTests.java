package dev.crain.authtracer.scan.spring;

import static dev.crain.authtracer.scan.FixtureScans.rule;
import static org.assertj.core.api.Assertions.assertThat;

import dev.crain.authtracer.graph.ApplicationGraph;
import dev.crain.authtracer.graph.AuthoritySource;
import dev.crain.authtracer.graph.AuthorizationLocation;
import dev.crain.authtracer.graph.Requirement.Kind;
import dev.crain.authtracer.scan.FixtureScans;
import org.junit.jupiter.api.Test;

class WebFluxFixtureTests {

    private final ApplicationGraph graph = FixtureScans.scan("webflux");

    @Test
    void authorizeExchangeRulesInOrder() {
        AuthorizationLocation staff = rule(graph, "GET /staff/list");
        assertThat(staff.mechanism()).isEqualTo("authorizeExchange");
        assertThat(staff.routePattern()).isEqualTo("/staff/**");
        assertThat(rule(graph, "POST /orders").requirement().authorities()).containsExactly("SCOPE_orders.write");
        assertThat(rule(graph, "GET /orders/{id}").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
        assertThat(rule(graph, "GET /legacy/items").requirement().kind()).isEqualTo(Kind.DENY_ALL);
        assertThat(rule(graph, "GET /public/info").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(graph, "GET /reports/daily").requirement().authorities())
                .containsExactlyInAnyOrder("ROLE_AUDITOR", "ROLE_ADMIN");
    }

    @Test
    void theReactiveDslIgnoresTheRoleHierarchy() {
        assertThat(rule(graph, "GET /staff/list").requirement().authorities()).containsExactly("ROLE_STAFF");
    }

    @Test
    void securityMatcherAndScopes() {
        assertThat(rule(graph, "GET /partner/data").requirement().authorities()).containsExactly("SCOPE_partner");
    }

    @Test
    void customizerBeansComeFirst() {
        assertThat(rule(graph, "GET /actuator/health").requirement().authorities()).containsExactly("ROLE_OPS");
        assertThat(rule(graph, "GET /ops/status").requirement().authorities()).containsExactly("ROLE_OPS2");
        assertThat(rule(graph, "GET /ops/status").target().method()).isEqualTo("ops()");
    }

    @Test
    void reactiveResourceServerIsTheAuthoritySource() {
        assertThat(graph.authoritySource().kind()).isEqualTo(AuthoritySource.Kind.JWT_CLAIMS);
        assertThat(graph.authoritySource().freshness()).isEqualTo(AuthoritySource.Freshness.SNAPSHOT);
    }

    @Test
    void theWebFluxDefaultChain() {
        ApplicationGraph defaults = FixtureScans.scan("webfluxdefault");
        assertThat(rule(defaults, "GET /docs/index").requirement().kind()).isEqualTo(Kind.PERMIT_ALL);
        assertThat(rule(defaults, "GET /data").mechanism()).isEqualTo("Spring Security default SecurityWebFilterChain");
        assertThat(rule(defaults, "GET /data").requirement().kind()).isEqualTo(Kind.AUTHENTICATED);
    }

    @Test
    void theWebApplicationTypePropertyChoosesTheStack() {
        // Both stacks are on the classpath, where Boot would pick the Servlet one.
        ApplicationGraph reactive = FixtureScans.scan("webapptype");
        assertThat(rule(reactive, "GET /quotes").mechanism()).isEqualTo("Spring Security default SecurityWebFilterChain");
        assertThat(rule(reactive, "GET /quotes").routePattern()).isEqualTo("anyExchange");
    }
}
